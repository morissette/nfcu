"""
NFCU example — demonstrates the full login flow and account data retrieval.

Credentials are loaded from .config/creds (gitignored):
  {"username": "your_username", "password": "your_password"}
"""
import json
import sys

import nfcu
from nfcu.exceptions import NFCUAuthError, NFCUMFAError


if __name__ == "__main__":
    # ── Load credentials ─────────────────────────────────────────────────────
    try:
        with open(".config/creds", encoding="utf-8") as creds_file:
            creds = json.load(creds_file)
    except (OSError, json.JSONDecodeError) as exc:
        sys.exit(f"Could not load .config/creds: {exc}")

    username = creds.get("username")
    password = creds.get("password")
    if not username or not password:
        sys.exit("Please configure .config/creds — see .config/creds-sample")

    # ── Authenticate ─────────────────────────────────────────────────────────
    client = nfcu.NFCU(username, password)

    try:
        phones = client.login()
    except NFCUAuthError as exc:
        sys.exit(f"Login failed: {exc}")

    print("MFA options:")
    for i, phone in enumerate(phones):
        print(f"  [{i}] {phone['phoneNumber']} ({phone['phoneType']})")

    # Request OTP on the first phone (index 0)
    client.request_otp()
    print("\nOTP sent via SMS.")

    otp = input("Enter OTP: ").strip()
    try:
        client.submit_mfa(otp)
    except NFCUMFAError as exc:
        sys.exit(f"MFA failed: {exc}")

    print("Authenticated.\n")

    # ── Account overview ──────────────────────────────────────────────────────
    accounts = client.get_accounts()
    products = accounts.get("products", [])

    print(f"{'Account':<40} {'Balance':>12}  ID")
    print("-" * 80)
    for p in products:
        name = p.get("alias") or p.get("name", "Unknown")
        balance = p.get("currentBalance", 0)
        account_id = p.get("id", "")
        print(f"{name:<40} ${balance:>11,.2f}  {account_id}")

    # ── Recent transactions for the first account ─────────────────────────────
    if products:
        first_id = products[0]["id"]
        first_name = products[0].get("alias") or products[0].get("name")
        txns = client.get_transactions(first_id, size=5)
        items = txns.get("transactionItems", [])

        print(f"\nLast {len(items)} transactions — {first_name}:")
        print("-" * 60)
        for t in items:
            date = t.get("bookingDate", "")
            desc = t.get("description", "")[:30]
            amount = t.get("transactionAmountCurrency", {}).get("amount", "0")
            sign = "+" if t.get("creditDebitIndicator") == "CRDT" else "-"
            print(f"  {date}  {desc:<30}  {sign}${float(amount):,.2f}")

    # ── User profile ──────────────────────────────────────────────────────────
    me = client.get_user()
    print(f"\nLogged in as: {me.get('fullName', username)}")

    client.logout()
    print("Session ended.")
