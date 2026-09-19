#!/usr/bin/env python3
"""
Biedronka ("Moja Biedronka") API CLI - multi-account session + Shakeomat automation.

Reverse-engineered from mitmproxy capture of the official Android app
(v2.22.2) traffic. See README.md in this folder for the full endpoint
writeup and how this was derived.

Auth: Keycloak OAuth2 Authorization Code + PKCE (realm "loyalty",
client_id "cma20", no client secret - public client). Login itself
(phone number + SMS OTP + Cloudflare Turnstile) can't be reliably
scripted headlessly, so this tool does a hybrid:
  1. `login --name NAME` prints an auth URL and opens it in your real browser.
  2. You log in normally (Turnstile solves itself in a real browser).
  3. Keycloak redirects to app://cma20.biedronka.pl?code=... which your
     browser can't open - copy that failed-navigation URL from the
     address bar and paste it back when prompted.
  4. `login-exchange NAME "<url>"` exchanges the code (+ the code_verifier
     it generated) for an access_token/refresh_token pair and saves it
     under NAME.

Multiple accounts are stored side by side (~/.config/biedronka-cli/accounts.json).
Every read/action command accepts `--account NAME` to target just one account;
omit it and the command runs across every saved account.

Usage:
  python3 biedronka_cli.py login --name myaccount
  python3 biedronka_cli.py login-exchange myaccount "app://cma20.biedronka.pl?code=...&session_state=..."
  python3 biedronka_cli.py accounts                       # list saved accounts
  python3 biedronka_cli.py remove myaccount                    # forget a saved account
  python3 biedronka_cli.py refresh [--account myaccount]
  python3 biedronka_cli.py me [--account myaccount]
  python3 biedronka_cli.py shake status [--account myaccount]  # find current shakeomat slot(s)
  python3 biedronka_cli.py shake check  [--account myaccount]  # is a shake available right now?
  python3 biedronka_cli.py shake now    [--account myaccount]  # shake + print the rolled product
  python3 biedronka_cli.py shake list   [--account myaccount]  # products already won today
  python3 biedronka_cli.py shake watch  [--account myaccount] [--interval 5] [--once]
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
# Fallback only - the real lookup is dynamic via _resolve_j4u_carousel_id(), because this
# is a CMS-driven content ID (from the dashboard's "Just4You" section), not a fixed constant.
J4U_CAROUSEL_ID_FALLBACK = "1ab93c45-e807-4ab0-b3a5-7011b0d7a36f"
J4U_CACHE_TTL = 600  # seconds - re-resolve periodically in case the CMS content changes

SESSION_DIR = os.environ.get("BIEDRONKA_HOME", os.path.expanduser("~/.config/biedronka-cli"))
ACCOUNTS_FILE = os.path.join(SESSION_DIR, "accounts.json")
LEGACY_SESSION_FILE = os.path.join(SESSION_DIR, "session.json")  # pre-multi-account format
ANDROID_UA = "Android/2.22.2"


# --------------------------------------------------------------------------
# Storage
# --------------------------------------------------------------------------

def _decode_jwt_claims(token: str) -> dict:
    try:
        payload = token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        return json.loads(base64.urlsafe_b64decode(payload))
    except Exception:
        return {}


def _empty_store() -> dict:
    return {"accounts": {}, "pending_logins": {}}


def _migrate_legacy_session(store: dict) -> bool:
    """One-time import of the old single-account session.json, if present."""
    if not os.path.exists(LEGACY_SESSION_FILE):
        return False
    with open(LEGACY_SESSION_FILE) as f:
        legacy = json.load(f)
    if "access_token" not in legacy:
        return False
    claims = _decode_jwt_claims(legacy["access_token"])
    name = (claims.get("given_name") or "default").lower()
    base_name, n = name, 1
    while name in store["accounts"]:
        n += 1
        name = f"{base_name}{n}"
    store["accounts"][name] = {
        "access_token": legacy["access_token"],
        "refresh_token": legacy["refresh_token"],
        "obtained_at": legacy.get("obtained_at", time.time()),
        "expires_in": legacy.get("expires_in"),
        "refresh_expires_in": legacy.get("refresh_expires_in"),
    }
    os.rename(LEGACY_SESSION_FILE, LEGACY_SESSION_FILE + ".migrated")
    print(f"Migrated existing session -> account '{name}'.", file=sys.stderr)
    return True


def _load_store() -> dict:
    if os.path.exists(ACCOUNTS_FILE):
        with open(ACCOUNTS_FILE) as f:
            store = json.load(f)
        store.setdefault("accounts", {})
        store.setdefault("pending_logins", {})
        return store
    store = _empty_store()
    if _migrate_legacy_session(store):
        _save_store(store)
    return store


def _save_store(store: dict) -> None:
    os.makedirs(SESSION_DIR, exist_ok=True)
    with open(ACCOUNTS_FILE, "w") as f:
        json.dump(store, f, indent=2)
    os.chmod(ACCOUNTS_FILE, stat.S_IRUSR | stat.S_IWUSR)


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _resolve_account_names(store: dict, explicit: str) -> list:
    if explicit:
        if explicit not in store["accounts"]:
            sys.exit(f"No saved account named '{explicit}'. Run `accounts` to list saved accounts.")
        return [explicit]
    names = list(store["accounts"].keys())
    if not names:
        sys.exit("No saved accounts. Run `login --name <name>` first.")
    return names


# --------------------------------------------------------------------------
# Login / account management
# --------------------------------------------------------------------------

def cmd_login(args) -> None:
    store = _load_store()
    name = args.name
    if name in store["accounts"]:
        sys.exit(f"Account '{name}' already exists. `remove {name}` first, or pick a different --name.")

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

    store["pending_logins"][name] = {"code_verifier": code_verifier}
    _save_store(store)

    print(f"Opening login page in your browser for account '{name}'...")
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
    print(f'  python3 biedronka_cli.py login-exchange {name} "<paste the app:// url here>"')


def cmd_login_exchange(args) -> None:
    store = _load_store()
    pending = store["pending_logins"].get(args.name)
    if not pending:
        sys.exit(f"No pending login for '{args.name}' (run `login --name {args.name}` first).")
    code_verifier = pending["code_verifier"]

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
    store["accounts"][args.name] = {
        "access_token": tokens["access_token"],
        "refresh_token": tokens["refresh_token"],
        "obtained_at": time.time(),
        "expires_in": tokens.get("expires_in"),
        "refresh_expires_in": tokens.get("refresh_expires_in"),
    }
    del store["pending_logins"][args.name]
    _save_store(store)
    print(f"Login successful, account '{args.name}' saved.")


def cmd_remove(args) -> None:
    store = _load_store()
    if args.name not in store["accounts"]:
        sys.exit(f"No saved account named '{args.name}'.")
    del store["accounts"][args.name]
    store["pending_logins"].pop(args.name, None)
    _save_store(store)
    print(f"Removed account '{args.name}'.")


def cmd_accounts(_args) -> None:
    store = _load_store()
    if not store["accounts"]:
        print("No saved accounts.")
        return
    now = time.time()
    for name, session in store["accounts"].items():
        obtained_at = session.get("obtained_at", 0)
        expires_in = session.get("expires_in", 0)
        access_valid = now < obtained_at + expires_in
        refresh_expires_in = session.get("refresh_expires_in", 0)
        refresh_valid = now < obtained_at + refresh_expires_in
        claims = _decode_jwt_claims(session.get("access_token", ""))
        card = claims.get("loyalty_card_number", "?")
        given_name = claims.get("given_name", "?")
        print(f"{name}: {given_name} (card {card}) - "
              f"access {'valid' if access_valid else 'expired'}, "
              f"refresh {'valid' if refresh_valid else 'EXPIRED (needs re-login)'}")


# --------------------------------------------------------------------------
# Token refresh + authenticated requests
# --------------------------------------------------------------------------

def _refresh_account(store: dict, name: str) -> dict:
    session = store["accounts"][name]
    resp = requests.post(
        f"{KEYCLOAK_BASE}/token",
        headers={"content-type": "application/x-www-form-urlencoded"},
        data={
            "grant_type": "refresh_token",
            "client_id": CLIENT_ID,
            "refresh_token": session["refresh_token"],
        },
    )
    resp.raise_for_status()
    tokens = resp.json()
    session.update(
        {
            "access_token": tokens["access_token"],
            "refresh_token": tokens.get("refresh_token", session["refresh_token"]),
            "obtained_at": time.time(),
            "expires_in": tokens.get("expires_in"),
            "refresh_expires_in": tokens.get("refresh_expires_in"),
        }
    )
    _save_store(store)
    return session


def _refresh_once(account: str) -> None:
    store = _load_store()
    for name in _resolve_account_names(store, account):
        _refresh_account(store, name)
        ts = time.strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{ts}] [{name}] Session refreshed.")


def cmd_refresh(args) -> None:
    if not args.daemon:
        _refresh_once(args.account)
        return

    # refresh_token lives ~120 days and rotates (a new one is issued) on every use,
    # which resets that window - so refreshing well inside it, forever, keeps the
    # session alive indefinitely without ever repeating the browser/Turnstile login.
    # This is a plain foreground loop by design: wrap it in whatever service manager
    # you prefer (systemd --user, launchd, a tmux session, cron @reboot + nohup, ...).
    interval = args.interval
    print(f"Daemon mode: refreshing every {interval}s (Ctrl+C to stop)...")
    _refresh_once(args.account)
    while True:
        time.sleep(interval)
        try:
            _refresh_once(args.account)
        except requests.RequestException as e:
            ts = time.strftime("%Y-%m-%d %H:%M:%S")
            print(f"[{ts}] Refresh failed, will retry next interval: {e}", file=sys.stderr)


def _ensure_fresh(store: dict, name: str) -> str:
    """Return a valid access_token for `name`, refreshing first if stale/near-expiry."""
    session = store["accounts"][name]
    obtained_at = session.get("obtained_at", 0)
    expires_in = session.get("expires_in", 0)
    if time.time() > obtained_at + max(expires_in - 60, 0):
        session = _refresh_account(store, name)
    return session["access_token"]


def _api(name: str, method: str, path: str, **kwargs) -> requests.Response:
    store = _load_store()
    token = _ensure_fresh(store, name)
    headers = kwargs.pop("headers", {})
    headers.setdefault("authorization", f"Bearer {token}")
    headers.setdefault("user-agent", ANDROID_UA)
    return requests.request(method, f"{API_BASE}{path}", headers=headers, **kwargs)


# --------------------------------------------------------------------------
# Account info
# --------------------------------------------------------------------------

def cmd_me(args) -> None:
    store = _load_store()
    names = _resolve_account_names(store, args.account)
    for name in names:
        if len(names) > 1:
            print(f"=== {name} ===")
        resp = _api(name, "GET", "/users/me/?refresh=false")
        resp.raise_for_status()
        print(json.dumps(resp.json(), indent=2, ensure_ascii=False))


# --------------------------------------------------------------------------
# Shakeomat
# --------------------------------------------------------------------------

_j4u_carousel_id_cache = {}  # account name -> {"id": ..., "resolved_at": ...}


def _resolve_j4u_carousel_id(name: str) -> str:
    cached = _j4u_carousel_id_cache.setdefault(name, {"id": None, "resolved_at": 0.0})
    if cached["id"] and time.time() - cached["resolved_at"] < J4U_CACHE_TTL:
        return cached["id"]

    resp = _api(name, "GET", "/dashboards/dashboard/")
    resp.raise_for_status()
    for section in resp.json().get("sections", []):
        if section.get("slug") == "Just4You" and section.get("type") == "Carousels":
            cached["id"] = section["param"]
            cached["resolved_at"] = time.time()
            return cached["id"]

    # CMS section not found (renamed/removed) - fall back to the last known-good ID.
    print(f"[{name}] Warning: 'Just4You' dashboard section not found, using fallback carousel ID.",
          file=sys.stderr)
    cached["id"] = J4U_CAROUSEL_ID_FALLBACK
    cached["resolved_at"] = time.time()
    return cached["id"]


def _carousel_items(name: str) -> list:
    carousel_id = _resolve_j4u_carousel_id(name)
    resp = _api(name, "GET", f"/promos/carousels/{carousel_id}/")
    resp.raise_for_status()
    return resp.json().get("items", [])


def _find_shakeomat_offer(name: str):
    """Return a pending (unrevealed) SHAKEOMAT item for `name`, or None."""
    for item in _carousel_items(name):
        if item.get("type") == "SHAKEOMAT":
            return item
    return None


def _claimed_shakeomat_items(name: str) -> list:
    """Already-revealed shakeomat items still shown in the carousel today."""
    return [
        item
        for item in _carousel_items(name)
        if item.get("from_shakeomat") and (item.get("offer_type") or "").startswith("SHAKEOMAT")
    ]


def _check_activation(name: str, offer_id: str) -> bool:
    resp = _api(name, "GET", f"/offers/{offer_id}/check-activation/")
    if resp.status_code == 204:
        return True
    if resp.status_code in (403, 404, 409):
        return False
    resp.raise_for_status()
    return False


def _reveal(name: str, offer_id: str):
    """Reveal+activate an offer. Returns the product dict, or None if the
    server says it's not actually available yet (check-activation's 204
    isn't a hard guarantee - reveal-and-activate can still 409)."""
    resp = _api(name, "PATCH", f"/offers/{offer_id}/reveal-and-activate/")
    if resp.status_code in (403, 404, 409):
        return None
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


def cmd_shake_status(args) -> None:
    store = _load_store()
    names = _resolve_account_names(store, args.account)
    for name in names:
        if len(names) > 1:
            print(f"=== {name} ===")
        item = _find_shakeomat_offer(name)
        if item:
            print("Pending slot (not yet shaken):")
            print(json.dumps(item, indent=2, ensure_ascii=False))
            continue
        claimed = _claimed_shakeomat_items(name)
        if claimed:
            print("No pending slot - all of today's shakeomats are already claimed:")
            for c in claimed:
                print(f"  [{c.get('offer_type')}] {c.get('name')} -> {c.get('price')} zl "
                      f"(valid until {c.get('end')})")
        else:
            print("No shakeomat slots visible right now (feature may be off today).")


def cmd_shake_check(args) -> None:
    store = _load_store()
    names = _resolve_account_names(store, args.account)
    for name in names:
        prefix = f"[{name}] " if len(names) > 1 else ""
        item = _find_shakeomat_offer(name)
        if not item:
            print(f"{prefix}no pending slot (already claimed today, or none scheduled)")
            continue
        available = _check_activation(name, item["offer_id"])
        print(f"{prefix}{'available' if available else 'not available yet'}")


def cmd_shake_now(args) -> None:
    store = _load_store()
    names = _resolve_account_names(store, args.account)
    for name in names:
        if len(names) > 1:
            print(f"=== {name} ===")
        item = _find_shakeomat_offer(name)
        if not item:
            print("No pending slot (already claimed today, or none scheduled).")
            continue
        offer_id = item["offer_id"]
        if not _check_activation(name, offer_id):
            print("Not available right now - try `shake watch` to wait for it.")
            continue
        product = _reveal(name, offer_id)
        if product is None:
            print("Not available right now (server rejected activation) - try `shake watch`.")
            continue
        _print_product(product)


def cmd_shake_list(args) -> None:
    store = _load_store()
    names = _resolve_account_names(store, args.account)
    for name in names:
        if len(names) > 1:
            print(f"=== {name} ===")
        claimed = _claimed_shakeomat_items(name)
        if not claimed:
            print("No shakeomat offers claimed today yet.")
            continue
        for c in claimed:
            print(f"[{c.get('offer_type')}] {c.get('name')}")
            print(f"  Price:      {c.get('price')} zl (regular {c.get('regular_price')} zl, "
                  f"{c.get('discount')}% off)")
            print(f"  Unit price: {c.get('unit_price')}")
            print(f"  Limit:      {c.get('limit_message')}")
            print(f"  Valid:      {c.get('start')} -> {c.get('end')}")
            print(f"  EAN:        {c.get('product_main_ean_code')}")
            print(f"  Image:      {c.get('image_url')}")
            print()


def cmd_shake_watch(args) -> None:
    store = _load_store()
    names = _resolve_account_names(store, args.account)
    print(f"Watching {', '.join(names)} for shakeomat slots, polling every {args.interval}s "
          "(Ctrl+C to stop)...")

    tracked = {name: None for name in names}  # name -> pending offer_id being waited on
    seen = {name: set() for name in names}
    done = set()  # names that finished (only relevant with --once)

    while True:
        for name in names:
            if name in done:
                continue
            if tracked[name] is None:
                item = _find_shakeomat_offer(name)
                if item and item["offer_id"] not in seen[name]:
                    tracked[name] = item["offer_id"]
                    print(f"[{name}] Found pending slot [{item.get('offer_type')}] "
                          f"{item['offer_id']} - waiting for it to open...")
                continue

            offer_id = tracked[name]
            if _check_activation(name, offer_id):
                product = _reveal(name, offer_id)
                if product is None:
                    # check-activation said yes but reveal still 409'd - not
                    # actually ready yet, keep tracking and retry next tick.
                    continue
                print(f"[{name}] Shaken:")
                _print_product(product)
                print()
                seen[name].add(offer_id)
                tracked[name] = None
                if args.once:
                    done.add(name)

        if args.once and done == set(names):
            return
        time.sleep(args.interval)


# --------------------------------------------------------------------------
# CLI wiring
# --------------------------------------------------------------------------

def _add_account_flag(p: argparse.ArgumentParser) -> None:
    p.add_argument("--account", default=None, help="Target only this saved account (default: all)")


def main() -> None:
    parser = argparse.ArgumentParser(description="Biedronka API CLI")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("login", help="Start browser login (OAuth2+PKCE) for a new account")
    p.add_argument("--name", required=True, help="Name to save this account under")
    p.set_defaults(func=cmd_login)

    p = sub.add_parser("login-exchange", help="Finish login with the pasted redirect URL/code")
    p.add_argument("name", help="Account name given to `login --name`")
    p.add_argument("redirect_or_code")
    p.set_defaults(func=cmd_login_exchange)

    p = sub.add_parser("remove", help="Forget a saved account")
    p.add_argument("name")
    p.set_defaults(func=cmd_remove)

    sub.add_parser("accounts", help="List saved accounts").set_defaults(func=cmd_accounts)

    p = sub.add_parser("refresh", help="Refresh the access token")
    _add_account_flag(p)
    p.add_argument("--daemon", action="store_true",
                    help="Keep running, refreshing on --interval forever (Ctrl+C to stop)")
    p.add_argument("--interval", type=float, default=86400.0,
                    help="Daemon mode refresh interval in seconds (default: 1 day)")
    p.set_defaults(func=cmd_refresh)

    p = sub.add_parser("me", help="Show account info")
    _add_account_flag(p)
    p.set_defaults(func=cmd_me)

    shake = sub.add_parser("shake", help="Shakeomat commands")
    shake_sub = shake.add_subparsers(dest="shake_command", required=True)

    p = shake_sub.add_parser("status", help="Show the current shakeomat offer slot")
    _add_account_flag(p)
    p.set_defaults(func=cmd_shake_status)

    p = shake_sub.add_parser("check", help="Check if a shake is available now")
    _add_account_flag(p)
    p.set_defaults(func=cmd_shake_check)

    p = shake_sub.add_parser("now", help="Shake immediately (fails if not available)")
    _add_account_flag(p)
    p.set_defaults(func=cmd_shake_now)

    p = shake_sub.add_parser("list", help="List products already won from shakeomat today")
    _add_account_flag(p)
    p.set_defaults(func=cmd_shake_list)

    p = shake_sub.add_parser("watch", help="Poll for shake slots and grab each one as it opens "
                                            "(runs until Ctrl+C)")
    _add_account_flag(p)
    p.add_argument("--interval", type=float, default=5.0, help="Polling interval in seconds")
    p.add_argument("--once", action="store_true", help="Stop after the first successful shake per account")
    p.set_defaults(func=cmd_shake_watch)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
