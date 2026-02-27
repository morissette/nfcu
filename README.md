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

client = NFCU("m0rissette", "my_password")

# 1. Login — returns MFA phone options
phones = client.login()
print(phones)  # [{"phoneNumber": "*7761", "phoneId": "..."}]

# 2. Request an OTP via SMS
client.request_otp()

# 3. Verify the OTP received by text message
client.submit_mfa(input("Enter OTP: "))

# 4. Fetch account balances
accounts = client.get_accounts()
for p in accounts["products"]:
    print(p["name"], p["currentBalance"])
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
{"username": "m0rissette", "password": "your_password"}
```

Example script: `example.py`
