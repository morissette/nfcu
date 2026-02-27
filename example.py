"""
Entrypoint for NFCU
"""
import json
import sys

import nfcu

if __name__ == "__main__":
    try:
        with open(".config/creds", encoding="utf-8") as creds_file:
            creds = json.load(creds_file)
    except (OSError, json.JSONDecodeError) as exc:
        sys.exit(f"Could not load .config/creds: {exc}")

    username = creds.get("username")
    password = creds.get("password")

    if not username or not password:
        sys.exit("Please configure .config/creds — see .config/creds-sample")

    bank = nfcu.NFCU(username, password)
    print(json.dumps(bank.get_account_summary(), indent=2))
