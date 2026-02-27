[![Build Status](https://travis-ci.org/morissette/nfcu.svg?branch=master)](https://travis-ci.org/morissette/nfcu)
[![Coverage Status](https://coveralls.io/repos/github/morissette/nfcu/badge.svg?branch=master)](https://coveralls.io/github/morissette/nfcu?branch=master)

# Navy Federal

Python client for the Navy Federal Credit Union mobile API — reverse-engineered
from the Android app (v2026.2.1) using mitmproxy.

> **Disclaimer**: Unofficial library.  Use only for authorised access to your
> own accounts.  See the [full API reference](docs/API.md) for details.

## Based On

Originally forked from the node version here:
<https://github.com/tjhorner/node-nfcu>

The old API (`mservices.navyfcu.org`) was tombstoned in January 2025.  This
rewrite targets the current Backbase microservices API at
`digitalomni.navyfederal.org`.

## Quick Start

```python
from nfcu import NFCU

client = NFCU("your_username", "your_password")

# 1. Login — returns MFA phone options
phones = client.login()
print(phones)  # [{"phoneNumber": "*1234", "phoneId": "..."}]

# 2. Request an OTP via SMS
client.request_otp()

# 3. Verify the OTP received by text message
client.submit_mfa(input("Enter OTP: "))

# 4. Fetch account balances
accounts = client.get_accounts()
for group in accounts["groups"].values():
    for acct in group["elements"]:
        attrs = acct["attributes"]
        name = attrs.get("alias", {}).get("value") or attrs.get("name", {}).get("value")
        bal  = attrs.get("bookedBalance", {}).get("value", "0")
        print(name, f"${float(bal):,.2f}")

# 5. Fetch cards and rewards balance
for card in client.get_cards():
    print(card["name"], card["maskedNumber"], card["status"])

rewards = client.get_card_rewards("2e2d1d00-0a50-4fe2-85d5-fb3fb915c56c")
print(f"Cash back: ${rewards['balance']}")
```

See [docs/API.md](docs/API.md) for the full method reference.

## Development

### Install dependencies

```bash
pipenv install --dev
```

### Run tests

```bash
pipenv run pytest test/
```

Tests are all mocked — no live API or credentials needed.

### Lint and style

```bash
pipenv run pylint nfcu/
pipenv run pycodestyle nfcu/
```

### Run everything (mirrors CI)

```bash
pipenv run pylint nfcu/ && pipenv run pycodestyle nfcu/ && pipenv run pytest test/
```

### Coverage report

```bash
pipenv run pytest test/ --cov=nfcu --cov-report=term-missing
```

## Traffic Capture / Reverse Engineering

To intercept and analyse NFCU app traffic yourself, see
[intercept/SETUP.md](intercept/SETUP.md).

## Credentials

Store credentials in `.config/creds` (gitignored):

```json
{"username": "your_username", "password": "your_password"}
```

Example script: `example.py`
