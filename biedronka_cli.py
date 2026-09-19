#!/usr/bin/env python3
"""
Biedronka ("Moja Biedronka") API CLI - session/login + Shakeomat automation.

Reverse-engineered from mitmproxy capture of the official Android app
(v2.22.2) traffic. See README.md in this folder for the full endpoint
writeup and how this was derived.

Auth: Keycloak OAuth2 Authorization Code + PKCE (realm "loyalty",
client_id "cma20", no client secret - public client). Login itself
(phone number + SMS OTP + Cloudflare Turnstile) can't be reliably
scripted headlessly, so this tool does a hybrid:
  1. `login` prints an auth URL and opens it in your real browser.
  2. You log in normally (Turnstile solves itself in a real browser).
  3. Keycloak redirects to app://cma20.biedronka.pl?code=... which your
     browser can't open - copy that failed-navigation URL from the
     address bar and paste it back when prompted.
  4. This tool exchanges the code (+ the code_verifier it generated) for
     an access_token/refresh_token pair and saves them locally.

After that, `refresh` renews the session (24h access token; refresh
token lives much longer) without repeating the browser step at all,
until the refresh token itself finally expires.

Usage:
  python3 biedronka_cli.py login
  python3 biedronka_cli.py login-exchange "app://cma20.biedronka.pl?code=...&session_state=..."
  python3 biedronka_cli.py refresh
  python3 biedronka_cli.py me
  python3 biedronka_cli.py shake status      # find current shakeomat slot + offer_id
  python3 biedronka_cli.py shake check        # is a shake available right now?
  python3 biedronka_cli.py shake now          # shake + print the rolled product
  python3 biedronka_cli.py shake watch [--interval 5]   # poll until available, then shake
"""
import argparse
import base64
import hashlib
import json
import os
import re
import secrets
import stat
import sys
import time
import urllib.parse
import webbrowser

import requests

KEYCLOAK_BASE = "https://konto.biedronka.pl/realms/loyalty/protocol/openid-connect"
CLIENT_ID = "cma20"
REDIRECT_URI = "app://cma20.biedronka.pl"
API_BASE = "https://api.prod.biedronka.cloud/api/v7"
J4U_CAROUSEL_ID = "1ab93c45-e807-4ab0-b3a5-7011b0d7a36f"  # "Just for you" - carries the SHAKEOMAT slot

SESSION_DIR = os.path.expanduser("~/.config/biedronka-cli")
SESSION_FILE = os.path.join(SESSION_DIR, "session.json")
ANDROID_UA = "Android/2.22.2"


def _save_session(data: dict) -> None:
    os.makedirs(SESSION_DIR, exist_ok=True)
    with open(SESSION_FILE, "w") as f:
        json.dump(data, f, indent=2)
    os.chmod(SESSION_FILE, stat.S_IRUSR | stat.S_IWUSR)


def _load_session() -> dict:
    if not os.path.exists(SESSION_FILE):
        sys.exit(f"No session found at {SESSION_FILE}. Run `login` first.")
    with open(SESSION_FILE) as f:
        return json.load(f)


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def cmd_login(_args) -> None:
    code_verifier = _b64url(secrets.token_bytes(32))
    code_challenge = _b64url(hashlib.sha256(code_verifier.encode()).digest())

    params = {
        "response_type": "code",
        "client_id": CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
    }
    auth_url = f"{KEYCLOAK_BASE}/auth?{urllib.parse.urlencode(params)}"

    # Stash the verifier so `login-exchange` can find it without you retyping it.
    _save_session({"pending_code_verifier": code_verifier})

    print("Opening login page in your browser...")
    print(auth_url)
    webbrowser.open(auth_url)
    print()
    print("Log in normally (phone number + SMS code).")
    print("After the final step, Keycloak will try to redirect to:")
    print(f"  {REDIRECT_URI}?code=...")
    print("Your browser can't open that (no app registered for app://) and will")
    print("show an error page / blank tab - that's expected. Copy the FULL URL")
    print("from the address bar (or the failed-navigation notice) and run:")
    print()
    print('  python3 biedronka_cli.py login-exchange "<paste the app:// url here>"')


def cmd_login_exchange(args) -> None:
    session = _load_session()
    code_verifier = session.get("pending_code_verifier")
    if not code_verifier:
        sys.exit("No pending login (run `login` first).")

    raw = args.redirect_or_code.strip()
    m = re.search(r"[?&]code=([^&\s]+)", raw)
    code = urllib.parse.unquote(m.group(1)) if m else raw
    if not code:
        sys.exit("Could not find a code in the input.")

    resp = requests.post(
        f"{KEYCLOAK_BASE}/token",
        headers={"content-type": "application/x-www-form-urlencoded"},
        data={
            "grant_type": "authorization_code",
            "client_id": CLIENT_ID,
            "redirect_uri": REDIRECT_URI,
            "code": code,
            "code_verifier": code_verifier,
        },
    )
    resp.raise_for_status()
    tokens = resp.json()
    _save_session(
        {
            "access_token": tokens["access_token"],
            "refresh_token": tokens["refresh_token"],
            "obtained_at": time.time(),
            "expires_in": tokens.get("expires_in"),
            "refresh_expires_in": tokens.get("refresh_expires_in"),
        }
    )
    print("Login successful, session saved.")


def cmd_refresh(_args) -> None:
    session = _load_session()
    refresh_token = session.get("refresh_token")
    if not refresh_token:
        sys.exit("No refresh_token saved (run `login` + `login-exchange` first).")

    resp = requests.post(
        f"{KEYCLOAK_BASE}/token",
        headers={"content-type": "application/x-www-form-urlencoded"},
        data={
            "grant_type": "refresh_token",
            "client_id": CLIENT_ID,
            "refresh_token": refresh_token,
        },
    )
    resp.raise_for_status()
    tokens = resp.json()
    session.update(
        {
            "access_token": tokens["access_token"],
            "refresh_token": tokens.get("refresh_token", refresh_token),
            "obtained_at": time.time(),
            "expires_in": tokens.get("expires_in"),
            "refresh_expires_in": tokens.get("refresh_expires_in"),
        }
    )
    _save_session(session)
    print("Session refreshed.")


def _ensure_fresh(session: dict) -> str:
    """Return a valid access_token, refreshing first if it's stale/near-expiry."""
    obtained_at = session.get("obtained_at", 0)
    expires_in = session.get("expires_in", 0)
    if time.time() > obtained_at + max(expires_in - 60, 0):
        cmd_refresh(None)
        session = _load_session()
    return session["access_token"]


def _api(method: str, path: str, **kwargs) -> requests.Response:
    session = _load_session()
    token = _ensure_fresh(session)
    headers = kwargs.pop("headers", {})
    headers.setdefault("authorization", f"Bearer {token}")
    headers.setdefault("user-agent", ANDROID_UA)
    return requests.request(method, f"{API_BASE}{path}", headers=headers, **kwargs)


def cmd_me(_args) -> None:
    resp = _api("GET", "/users/me/?refresh=false")
    resp.raise_for_status()
    print(json.dumps(resp.json(), indent=2, ensure_ascii=False))


def _carousel_items() -> list:
    resp = _api("GET", f"/promos/carousels/{J4U_CAROUSEL_ID}/")
    resp.raise_for_status()
    return resp.json().get("items", [])


def _find_shakeomat_offer():
    """Return a pending (unrevealed) SHAKEOMAT item, or None if none is pending."""
    for item in _carousel_items():
        if item.get("type") == "SHAKEOMAT":
            return item
    return None


def _claimed_shakeomat_items() -> list:
    """Already-revealed shakeomat items still shown in the carousel today."""
    return [
        item
        for item in _carousel_items()
        if item.get("from_shakeomat") and (item.get("offer_type") or "").startswith("SHAKEOMAT")
    ]


def cmd_shake_status(_args) -> None:
    item = _find_shakeomat_offer()
    if item:
        print("Pending slot (not yet shaken):")
        print(json.dumps(item, indent=2, ensure_ascii=False))
        return
    claimed = _claimed_shakeomat_items()
    if claimed:
        print("No pending slot - all of today's shakeomats are already claimed:")
        for c in claimed:
            print(f"  [{c.get('offer_type')}] {c.get('name')} -> {c.get('price')} zl "
                  f"(valid until {c.get('end')})")
    else:
        print("No shakeomat slots visible right now (feature may be off today).")


def _check_activation(offer_id: str) -> bool:
    resp = _api("GET", f"/offers/{offer_id}/check-activation/")
    if resp.status_code == 204:
        return True
    if resp.status_code in (403, 404, 409):
        return False
    resp.raise_for_status()
    return False


def cmd_shake_check(_args) -> None:
    item = _find_shakeomat_offer()
    if not item:
        print("no pending slot (already claimed today, or none scheduled)")
        return
    available = _check_activation(item["offer_id"])
    print("available" if available else "not available yet")


def _reveal(offer_id: str) -> dict:
    resp = _api("PATCH", f"/offers/{offer_id}/reveal-and-activate/")
    resp.raise_for_status()
    return resp.json()


def _print_product(product: dict) -> None:
    print(f"Product:      {product.get('name')}")
    print(f"Price:        {product.get('price')} zl (regular {product.get('regular_price')} zl, "
          f"{product.get('discount')}% off)")
    print(f"Unit price:   {product.get('unit_price')}")
    print(f"Limit:        {product.get('limit_message')}")
    print(f"Valid:        {product.get('start')} -> {product.get('end')}")
    print(f"EAN:          {product.get('product_main_ean_code')}")
    print(f"Image:        {product.get('image_url')}")


def cmd_shake_now(_args) -> None:
    item = _find_shakeomat_offer()
    if not item:
        sys.exit("No pending slot (already claimed today, or none scheduled).")
    offer_id = item["offer_id"]
    if not _check_activation(offer_id):
        sys.exit("Not available right now - try `shake watch` to wait for it.")
    product = _reveal(offer_id)
    _print_product(product)


def cmd_shake_list(_args) -> None:
    claimed = _claimed_shakeomat_items()
    if not claimed:
        print("No shakeomat offers claimed today yet.")
        return
    for c in claimed:
        print(f"[{c.get('offer_type')}] {c.get('name')}")
        print(f"  Price:      {c.get('price')} zl (regular {c.get('regular_price')} zl, {c.get('discount')}% off)")
        print(f"  Unit price: {c.get('unit_price')}")
        print(f"  Limit:      {c.get('limit_message')}")
        print(f"  Valid:      {c.get('start')} -> {c.get('end')}")
        print(f"  EAN:        {c.get('product_main_ean_code')}")
        print(f"  Image:      {c.get('image_url')}")
        print()


def _wait_for_pending_slot(interval: float) -> dict:
    while True:
        item = _find_shakeomat_offer()
        if item:
            return item
        time.sleep(interval)


def _wait_and_reveal(offer_id: str, interval: float) -> dict:
    while True:
        if _check_activation(offer_id):
            return _reveal(offer_id)
        time.sleep(interval)


def cmd_shake_watch(args) -> None:
    print(f"Watching for shakeomat slots, polling every {args.interval}s (Ctrl+C to stop)...")
    seen_offer_ids = set()
    while True:
        item = _wait_for_pending_slot(args.interval)
        offer_id = item["offer_id"]
        if offer_id in seen_offer_ids:
            # already handled this one this run (carousel hasn't updated yet) - avoid a tight loop
            time.sleep(args.interval)
            continue
        print(f"Found pending slot [{item.get('offer_type')}] {offer_id} - waiting for it to open...")
        product = _wait_and_reveal(offer_id, args.interval)
        print("Shaken:")
        _print_product(product)
        print()
        seen_offer_ids.add(offer_id)
        if args.once:
            return
        print("Back to watching for the next slot...")


def main() -> None:
    parser = argparse.ArgumentParser(description="Biedronka API CLI")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("login", help="Start browser login (OAuth2+PKCE)").set_defaults(func=cmd_login)

    p = sub.add_parser("login-exchange", help="Finish login with the pasted redirect URL/code")
    p.add_argument("redirect_or_code")
    p.set_defaults(func=cmd_login_exchange)

    sub.add_parser("refresh", help="Refresh the access token").set_defaults(func=cmd_refresh)
    sub.add_parser("me", help="Show account info").set_defaults(func=cmd_me)

    shake = sub.add_parser("shake", help="Shakeomat commands")
    shake_sub = shake.add_subparsers(dest="shake_command", required=True)
    shake_sub.add_parser("status", help="Show the current shakeomat offer slot").set_defaults(func=cmd_shake_status)
    shake_sub.add_parser("check", help="Check if a shake is available now").set_defaults(func=cmd_shake_check)
    shake_sub.add_parser("now", help="Shake immediately (fails if not available)").set_defaults(func=cmd_shake_now)
    shake_sub.add_parser("list", help="List products already won from shakeomat today").set_defaults(func=cmd_shake_list)
    w = shake_sub.add_parser("watch", help="Poll until available, then shake")
    w.add_argument("--interval", type=float, default=5.0, help="Polling interval in seconds")
    w.set_defaults(func=cmd_shake_watch)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
