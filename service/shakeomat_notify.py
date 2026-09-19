"""
Long-running Shakeomat watcher for all accounts saved in biedronka_cli's
account store (BIEDRONKA_HOME/accounts.json, a Docker volume in this
container - see docker-compose.yml).

Every REFRESH_INTERVAL_SECONDS: refresh every account's access token
(refresh_token rotates on use and resets its own ~120 day expiry, so this
alone keeps every session alive indefinitely - see biedronka_cli.py).

Every CHECK_INTERVAL_SECONDS: look for a pending (unrevealed) SHAKEOMAT
slot per account. Once one appears, poll check-activation until it's
actually activatable, shake it (reveal-and-activate), and email an HTML
notification with the product name/price/image to EMAIL_TO.

No accounts can be added from inside the container - `login`/`login-exchange`
need a real browser for the Cloudflare Turnstile step. Add accounts on your
own machine with biedronka_cli.py and scp/copy accounts.json onto this
service's data volume.
"""
import logging
import os
import smtplib
import time
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

import biedronka_cli as b

REFRESH_INTERVAL_SECONDS = int(os.environ.get("REFRESH_INTERVAL_SECONDS", 12 * 3600))
CHECK_INTERVAL_SECONDS = int(os.environ.get("CHECK_INTERVAL_SECONDS", 15))

SMTP_HOST = os.environ["SMTP_HOST"]
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USERNAME = os.environ["SMTP_USERNAME"]
SMTP_PASSWORD = os.environ["SMTP_PASSWORD"]
EMAIL_FROM = os.environ.get("EMAIL_FROM", SMTP_USERNAME)
EMAIL_TO = os.environ["EMAIL_TO"]

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("biedronka-shakeomat")


def send_html_email(subject: str, html_body: str, text_body: str) -> None:
    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = EMAIL_FROM
    msg["To"] = EMAIL_TO
    msg.attach(MIMEText(text_body, "plain"))
    msg.attach(MIMEText(html_body, "html"))

    server_cls = smtplib.SMTP_SSL if SMTP_PORT == 465 else smtplib.SMTP
    with server_cls(SMTP_HOST, SMTP_PORT, timeout=30) as server:
        if SMTP_PORT != 465:
            server.starttls()
        server.login(SMTP_USERNAME, SMTP_PASSWORD)
        server.sendmail(EMAIL_FROM, [EMAIL_TO], msg.as_string())


def notify_shake(account_name: str, product: dict) -> None:
    name = product.get("name")
    price = product.get("price")
    regular = product.get("regular_price")
    discount = product.get("discount")
    unit_price = product.get("unit_price")
    limit = product.get("limit_message")
    valid_end = product.get("end")
    ean = product.get("product_main_ean_code")
    image = product.get("image_url")

    subject = f"Shakeomat [{account_name}]: {name}"
    text_body = (
        f"{name}\n"
        f"{price} zl (regular {regular} zl, {discount}% off)\n"
        f"{unit_price}\n{limit}\nValid until {valid_end}\nEAN {ean}\n{image}"
    )
    html_body = f"""\
<div style="font-family:sans-serif;max-width:480px">
  <h2 style="margin:0 0 8px">{name}</h2>
  <img src="{image}" alt="{name}" style="max-width:100%;border-radius:8px" />
  <p style="font-size:20px;margin:12px 0 4px">
    <b>{price} zl</b>
    <span style="color:#888;text-decoration:line-through;margin-left:8px">{regular} zl</span>
    <span style="color:#e30613;margin-left:8px">-{discount}%</span>
  </p>
  <p style="color:#555;margin:0">{unit_price}</p>
  <p style="color:#555;margin:4px 0">{limit}</p>
  <p style="color:#888;font-size:12px">Valid until {valid_end} - EAN {ean}</p>
  <p style="color:#aaa;font-size:11px">Account: {account_name}</p>
</div>
"""
    send_html_email(subject, html_body, text_body)
    log.info("[%s] notification email sent for %s", account_name, name)


def refresh_all() -> None:
    store = b._load_store()
    for name in list(store["accounts"].keys()):
        try:
            b._refresh_account(store, name)
            log.info("[%s] token refreshed", name)
        except Exception:
            log.exception("[%s] token refresh failed", name)


def check_and_shake(tracked: dict) -> None:
    store = b._load_store()
    for name in list(store["accounts"].keys()):
        try:
            if tracked.get(name) is None:
                item = b._find_shakeomat_offer(name)
                if item:
                    tracked[name] = item["offer_id"]
                    log.info("[%s] pending slot found: [%s] %s - waiting for it to open",
                             name, item.get("offer_type"), item["offer_id"])
                continue

            offer_id = tracked[name]
            if b._check_activation(name, offer_id):
                product = b._reveal(name, offer_id)
                if product is None:
                    # check-activation's 204 was optimistic - still not really ready
                    continue
                log.info("[%s] shaken: %s", name, product.get("name"))
                notify_shake(name, product)
                tracked[name] = None
        except Exception:
            log.exception("[%s] check/shake cycle failed", name)


def main() -> None:
    log.info(
        "Starting biedronka-shakeomat watcher: refresh every %ss, check every %ss, accounts store at %s",
        REFRESH_INTERVAL_SECONDS, CHECK_INTERVAL_SECONDS, b.ACCOUNTS_FILE,
    )
    tracked: dict = {}
    last_refresh = 0.0
    while True:
        now = time.time()
        if now - last_refresh >= REFRESH_INTERVAL_SECONDS:
            refresh_all()
            last_refresh = now
        check_and_shake(tracked)
        time.sleep(CHECK_INTERVAL_SECONDS)


if __name__ == "__main__":
    main()
