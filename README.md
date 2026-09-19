# biedronka-cli

An unofficial CLI for the "Moja Biedronka" loyalty app's backend API, built by
reverse-engineering the official Android app's traffic (mitmproxy capture,
v2.22.2). Handles login, multi-account session management, and the
"Shakeomat" daily promo feature (find/check/claim your store's personalized
offer of the day).

## How auth works

Login is Keycloak OAuth2 (Authorization Code + PKCE), realm `loyalty`,
public client `cma20`. The password step is gated by a Cloudflare Turnstile
challenge, which can't be reliably solved headlessly - so this tool does a
hybrid flow instead of a fully scripted login:

1. `login --name NAME` generates a PKCE pair and opens the real auth URL in
   your browser.
2. You log in normally (phone number + SMS code). Turnstile solves itself
   because it's a real browser.
3. Keycloak redirects to `app://cma20.biedronka.pl?code=...`, which your
   browser can't open - that's expected. Copy the failed-navigation URL from
   the address bar.
4. `login-exchange NAME "<that url>"` exchanges the code (+ the saved
   `code_verifier`) for an access/refresh token pair and saves it locally.

After that, `refresh_token` rotates on every use and resets its own ~120-day
expiry, so periodic refreshing (see `refresh --daemon`) keeps a session
alive indefinitely without ever repeating the browser step.

Sessions are stored in `~/.config/biedronka-cli/accounts.json` (override
with `BIEDRONKA_HOME`), `chmod 600`. Never commit this file - it holds live
bearer/refresh tokens.

## Setup

```
pip install requests
python3 biedronka_cli.py login --name myaccount
# ... log in in the browser, copy the redirected URL ...
python3 biedronka_cli.py login-exchange myaccount "app://cma20.biedronka.pl?code=...&session_state=..."
```

## Usage

```
python3 biedronka_cli.py accounts                        # list saved accounts
python3 biedronka_cli.py remove NAME                      # forget an account
python3 biedronka_cli.py refresh [--account NAME]          # refresh token(s); default: all
python3 biedronka_cli.py refresh --daemon [--interval S]   # keep refreshing forever (foreground)
python3 biedronka_cli.py me [--account NAME]

python3 biedronka_cli.py shops search [--query TEXT] [--lat LAT] [--lon LON]
python3 biedronka_cli.py shops show CODE
python3 biedronka_cli.py set-store CODE --account NAME      # sets which store's promo pool an account sees

python3 biedronka_cli.py shake status [--account NAME]      # pending slot info, or what's already been claimed today
python3 biedronka_cli.py shake check  [--account NAME]      # is a pending slot activatable right now?
python3 biedronka_cli.py shake now    [--account NAME]      # claim it immediately (fails if not ready)
python3 biedronka_cli.py shake list   [--account NAME]      # products already won today
python3 biedronka_cli.py shake watch  [--account NAME] [--interval S] [--once]
```

Every read/action command targets **all** saved accounts by default; pass
`--account NAME` to scope it to one.

Note: "Shakeomat" isn't actually randomized per account - it's a fixed daily
pair of deals scoped to the account's `preferred_store`. Accounts on the
same store (or with none set) will get identical results; use `set-store` to
diversify.

## `service/` - containerized watcher

A long-running Docker service (`shakeomat_notify.py`) that:

- refreshes every saved account's token on `REFRESH_INTERVAL_SECONDS`
  (default 12h - comfortably inside the refresh token's ~120-day window)
- polls every `CHECK_INTERVAL_SECONDS` for a pending Shakeomat slot per
  account, claims it the moment it's actually activatable
- emails an HTML notification (product name/price/image) per claim

See `service/.env.example` for configuration. It reads/writes
`accounts.json` from a mounted volume (`./data`) - copy your own
`~/.config/biedronka-cli/accounts.json` there; new accounts still have to be
added from a real machine (the browser/Turnstile step can't run in the
container).

```
cd service
cp .env.example .env   # fill in SMTP settings
cp ~/.config/biedronka-cli/accounts.json data/accounts.json
docker compose up -d --build
```

## How this was derived

The full endpoint surface (auth flow, `/api/v7/...` REST API, Shakeomat
mechanics) was mapped by running the official app through mitmproxy with a
rooted device (system-level CA trust, no pinning to bypass - Biedronka's app
doesn't pin certs) and inspecting the captured request/response bodies.
