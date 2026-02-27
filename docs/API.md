# NFCU Python API Reference

> **Reverse-engineered** — This library targets the Navy Federal Credit Union
> mobile app API (Android v2026.2.1, `digitalomni.navyfederal.org`).  It is an
> unofficial client; use it only for authorised access to your own accounts.

---

## Table of Contents

- [Quick Start](#quick-start)
- [Authentication Flow](#authentication-flow)
- [Class: `NFCU`](#class-nfcu)
  - [Constructor](#constructor)
  - [login()](#login)
  - [request_otp()](#request_otp)
  - [submit_mfa()](#submit_mfa)
  - [get_accounts()](#get_accounts)
  - [get_account()](#get_account)
  - [get_transactions()](#get_transactions)
  - [get_card_rewards()](#get_card_rewards)
  - [get_user()](#get_user)
  - [get_messages_indicator()](#get_messages_indicator)
  - [logout()](#logout)
- [Device Fingerprint](#device-fingerprint)
  - [Format](#format)
  - [Parameters](#parameters)
  - [Providing Your Own Fingerprint](#providing-your-own-fingerprint)
- [Exceptions](#exceptions)
- [Known Account IDs](#known-account-ids)
- [HTTP Headers Reference](#http-headers-reference)
- [API Endpoints Reference](#api-endpoints-reference)

---

## Quick Start

```python
from nfcu import NFCU

client = NFCU("your_username", "your_password")

# Step 1: initiate login, get MFA phone options
phone_options = client.login()
print(phone_options)
# [{"phoneNumber": "*1234", "phoneType": "M",
#   "phoneId": "cGhvbmUtaWQtcGxhY2Vob2xkZXI=..."}]

# Step 2: request OTP
client.request_otp()  # uses first option by default

# Step 3: enter OTP from SMS
client.submit_mfa(input("Enter OTP: "))

# Step 4: use the API
accounts = client.get_accounts()
for product in accounts.get("products", []):
    print(product["name"], product.get("currentBalance"))
```

---

## Authentication Flow

The NFCU mobile API uses a **five-step authentication flow** before any banking
endpoints are accessible.  Each step rotates the Bearer token.

```
Client                           Server
  |                                |
  |  POST /api/auth/mobile/authn   |
  |  {username, password,          |  ← Bearer token 1 returned in
  |   deviceFingerprint}           |    `authorization` response header
  |                                |
  |  GET  /api/auth/tfa/options    |  ← Returns list of phone numbers
  |                                |
  |  POST /api/auth/tfa/           |
  |       challenge/otp            |  ← Server sends SMS to chosen number
  |  {phoneId, otpType:"SMS"}      |
  |                                |
  |  POST /api/auth/tfa/           |
  |       challenge/verification   |  ← Bearer token 2 in response header
  |  {tfaType:"OTP", otp:"123456"} |
  |                                |
  |  GET  /api/auth/esi/activation |
  |  (called up to 3 times)        |  ← Bearer token 3 in 3rd response header
  |                                |    (this is the session token)
  |                                |
  |  POST /api/auth/tfa/decision   |  ← Optional risk assessment
  |  {eventId, denyRisk:true}      |
  |                                |
  |  ← Banking API now accessible  |
```

> **Token rotation**: Three different Bearer tokens are issued across the auth
> flow.  The library manages these automatically via `_update_auth_state()`.

---

## Class: `NFCU`

```python
from nfcu import NFCU
```

### Constructor

```python
NFCU(
    username: str,
    password: str,
    device_fingerprint: str = EMULATOR_FINGERPRINT,
    device_metadata: dict | None = None,
)
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `username` | `str` | NFCU online username |
| `password` | `str` | Account password |
| `device_fingerprint` | `str` | `_v02` fingerprint string (see [Device Fingerprint](#device-fingerprint)) |
| `device_metadata` | `dict \| None` | JSON blob for `x-nf-device-metadata` header |

The constructor does **not** perform authentication.  Call `login()` next.

---

### `login()`

```python
phones = client.login() -> list[dict]
```

Sends credentials and the device fingerprint.  Returns the list of phone
numbers eligible for OTP delivery.

**Returns** `list[dict]` — each entry:

```json
{
  "phoneNumber": "*1234",
  "phoneType": "M",
  "phoneId": "cGhvbmUtaWQtcGxhY2Vob2xkZXI="
}
```

| Field | Description |
|-------|-------------|
| `phoneNumber` | Masked phone number |
| `phoneType` | `"M"` (mobile) or `"H"` (home) |
| `phoneId` | Base64 token passed to `request_otp()` |

**Raises** `NFCUAuthError` on bad credentials.

---

### `request_otp()`

```python
result = client.request_otp(phone_id: str | None = None) -> dict
```

Asks the server to send an OTP SMS to the selected phone.

| Parameter | Default | Description |
|-----------|---------|-------------|
| `phone_id` | `None` | `phoneId` from `login()`.  Defaults to first option. |

**Returns**:

```json
{"expiration": 360, "message": "Success"}
```

**Raises** `NFCUAuthError` if called before `login()`.

---

### `submit_mfa()`

```python
result = client.submit_mfa(otp: str, remember_device: bool = False) -> dict
```

Completes the authentication flow by verifying the SMS OTP.  Internally
handles the ESI activation token rotation and TFA decision step.

| Parameter | Default | Description |
|-----------|---------|-------------|
| `otp` | *(required)* | 6-digit code from SMS |
| `remember_device` | `False` | Request server to remember device (requires device screen lock; emulator support limited) |

**Returns** verification response:

```json
{"name": "MARIE", "message": "Success", "token": "<bearer-token>"}
```

**Raises** `NFCUMFAError` on invalid or expired OTP.

---

### `get_accounts()`

```python
data = client.get_accounts() -> dict
```

Returns an overview of all accounts with current balances.

**Endpoint**: `GET /api/arrangement-manager/client-api/v2/arrangement-views/account-overview`

**Returns** dict with `products` list.  Each product:

```json
{
  "id": "0a2c476a-d3bd-4a7a-9e1e-dca25ab0060a",
  "name": "Flagship Checking",
  "alias": "Flagship Checking - 1107",
  "currentBalance": 1234.56,
  "availableBalance": 1200.00,
  "accountNumber": "XXXX1107",
  "productKindName": "Current Account"
}
```

---

### `get_account()`

```python
detail = client.get_account(account_id: str) -> dict
```

Returns full arrangement details for one account.

**Endpoint**: `GET /api/arrangement-manager/client-api/v2/arrangements/{account_id}`

| Parameter | Description |
|-----------|-------------|
| `account_id` | UUID from `get_accounts()` |

---

### `get_transactions()`

```python
txns = client.get_transactions(
    account_id: str,
    from_: int = 0,
    size: int = 25,
) -> dict
```

Returns paginated transactions for an account, newest first.

**Endpoint**: `GET /api/transaction-manager/client-api/v2/transactions`

| Parameter | Default | Description |
|-----------|---------|-------------|
| `account_id` | *(required)* | UUID from `get_accounts()` |
| `from_` | `0` | Zero-based page offset |
| `size` | `25` | Page size |

**Returns** dict with `transactionItems`:

```json
{
  "totalElements": 487,
  "transactionItems": [
    {
      "id": "tx-uuid",
      "bookingDate": "2026-02-27",
      "description": "AMAZON.COM",
      "creditDebitIndicator": "DBIT",
      "transactionAmountCurrency": {"amount": "42.99", "currencyCode": "USD"},
      "runningBalance": 1157.01
    }
  ]
}
```

**Pagination example**:

```python
all_txns = []
page = 0
while True:
    result = client.get_transactions(account_id, from_=page * 25, size=25)
    all_txns.extend(result["transactionItems"])
    if len(all_txns) >= result["totalElements"]:
        break
    page += 1
```

---

### `get_card_rewards()`

```python
rewards = client.get_card_rewards(account_id: str) -> dict
```

Returns rewards/cash-back information for a credit card account.

**Endpoint**: `GET /api/cards-presentation-service/client-api/v2/rewards/{account_id}`

---

### `get_user()`

```python
me = client.get_user() -> dict
```

Returns profile information for the authenticated member.

**Endpoint**: `GET /api/user-manager/client-api/v2/users/me`

---

### `get_messages_indicator()`

```python
indicator = client.get_messages_indicator() -> dict
```

Returns the unread secure-message count.

**Returns**: `{"unreadCount": 3}`

---

### `logout()`

```python
client.logout()
```

Invalidates the server-side session and clears all local tokens.

---

## Device Fingerprint

### Format

The `deviceFingerprint` field in every login request is a custom binary-in-text
encoding.  Layers from outside in:

```
_v02 + base64( XOR(plaintext, 0x55) )
```

The **plaintext** is a URL query string:

```
fpdt=2&mfos=Android&mfov=14&...&mfec=<rsa-signature>
```

### Parameters

| Parameter | Example | Description |
|-----------|---------|-------------|
| `fpdt` | `2` | Fingerprint data type |
| `mfos` | `Android` | OS name |
| `mfov` | `14` | OS version |
| `mfwa` | `02:00:00:00:00:00` | WiFi MAC address |
| `mfsc` | `2209\|1080` | Screen size (width\|height px) |
| `fpln` | `en_US` | Device locale |
| `mfgc` | `00.0000\|00.0000` | GPS coordinates (lat\|lon) |
| `mfpv` | `2` | Protocol version |
| `fpts` | `1772171439981` | Unix timestamp in milliseconds |
| `mfappid` | `com.navyfederal.android` | App bundle ID |
| `mfa_isrooted` | `false` | Root detection result |
| `mfa_id` | `3212038e3f2f8791` | Android hardware ID |
| `mfa_bd` | `goldfish_arm64` | `Build.DEVICE` |
| `mfa_br` | `google` | `Build.BRAND` |
| `mfa_ca1` | `arm64-v8a` | Primary CPU ABI |
| `mfa_fp` | `google/sdk_gphone64_arm64/...` | `Build.FINGERPRINT` |
| `mfa_dv` | `emu64a` | Device variant |
| `mfa_dp` | `sdk_gphone64_arm64-userdebug...` | Full build description |
| `mfa_mf` | `Google` | `Build.MANUFACTURER` |
| `mfa_md` | `sdk_gphone64_arm64` | `Build.MODEL` |
| `mfa_tags` | `dev-keys` | `Build.TAGS` |
| `mfa_bl` | `unknown` | `Build.BOOTLOADER` |
| `mfa_hw` | `ranchu` | `Build.HARDWARE` |
| `mfa_sci` | `us` | SIM country ISO |
| `mfa_spn` | `T-Mobile` | SIM carrier name |
| `mfa_so` | `310260` | SIM operator numeric |
| `mfec` | `Q2Pm...CQ==` | RSA-2048 signature (base64) |

### The `mfec` Signature

The `mfec` parameter is a 256-byte (2048-bit) **RSA signature** over all
preceding parameters (the query string before `&mfec=`).  The private key is
embedded in the NFCU Android APK.

Because the timestamp (`fpts`) is part of the signed payload, the signature
changes on every request.  Without the APK private key, fresh signatures cannot
be generated.

**The library ships with a captured emulator fingerprint** (`EMULATOR_FINGERPRINT`
in `nfcu/fingerprint.py`) that can be used for development/testing.  The server
may accept it even with an older timestamp, or may require a fresh one.

### Providing Your Own Fingerprint

To capture a real device fingerprint:

1. Run `intercept/start.sh` (see [intercept/SETUP.md](../intercept/SETUP.md))
2. Install the NFCU app and log in through the emulator
3. Find the `POST /api/auth/mobile/authn` flow in mitmweb (`localhost:8081`)
4. Extract the `deviceFingerprint` value from the request body
5. Pass it to `NFCU(..., device_fingerprint=your_fp)`

To decode any fingerprint for inspection:

```python
from nfcu.fingerprint import decode
plaintext = decode("_v02MyUx...")
print(plaintext)
# fpdt=2&mfos=Android&mfov=14&...
```

---

## Exceptions

| Exception | Inherits | When raised |
|-----------|----------|-------------|
| `NFCUAuthError` | `Exception` | Bad credentials or missing auth state |
| `NFCUSessionExpiredError` | `NFCUAuthError` | HTTP 401 after token was set |
| `NFCUMFAError` | `Exception` | Invalid or expired OTP |
| `NFCURateLimitError` | `Exception` | HTTP 429 Too Many Requests |
| `NFCUAPIError` | `Exception` | Any other non-2xx response |
| `NFCULoginError` | `Exception` | Legacy; prefer `NFCUAuthError` |
| `NFCUGetError` | `Exception` | Legacy; prefer `NFCUAPIError` |
| `NFCUPostError` | `Exception` | Legacy; prefer `NFCUAPIError` |

`NFCUAPIError` exposes `status_code` and `body` attributes:

```python
try:
    client.get_accounts()
except NFCUAPIError as e:
    print(e.status_code, e.body[:100])
```

---

## Known Account IDs

These UUIDs were observed during traffic capture on 2026-02-27 for
a specific member account.  They will differ for all members.

| Account | Display Name | UUID |
|---------|-------------|------|
| Flagship Checking | `Flagship Checking - 1107` | `0a2c476a-d3bd-4a7a-9e1e-dca25ab0060a` |
| Easy Checking | `Easy Checking - 7514` | `f9fbaf68-95bf-4d32-8901-9c1519d6a951` |
| Savings (6277) | `Membership Share Savings - 6277` | `31a9b8fe-7487-4cb7-8c32-ffd3c33903bf` |
| Savings (8330) | `Membership Share Savings - 8330` | `4e345276-78f2-42c6-98c6-46a90737809a` |
| cashRewards Visa | `cashRewards Secured Visa` | `2e2d1d00-0a50-4fe2-85d5-fb3fb915c56c` |

Account IDs are available at runtime via `get_accounts()["products"][n]["id"]`.

---

## HTTP Headers Reference

Every request after authentication must include:

| Header | Value | Notes |
|--------|-------|-------|
| `authorization` | `Bearer <token>` | Rotated across auth steps |
| `x-xsrf-token` | 32–64 char hex | Must match `XSRF-TOKEN` cookie (double-submit CSRF pattern) |
| `x-nf-profile-tag` | 32 char hex | Changes after OTP verification |
| `x-nf-device-metadata` | Base64 JSON | See below |
| `cid` | `Mobile` | Client identifier |
| `platform` | `AND` | Platform code for Android |
| `appversion` | `2026.2.1` | Must match current app version |
| `user-agent` | `NavyFederal/2026.2.1 (Android 14)` | |
| `content-type` | `application/json` | |

**`x-nf-device-metadata`** decodes to:

```json
{
  "name": "Google",
  "model": "sdk_gphone64_arm64",
  "platform": "AND",
  "multitask": true,
  "systemName": "Android",
  "systemVersion": "14",
  "screenSize": "2209x1080",
  "language": "en",
  "ipAddress": "10.0.2.15",
  "hardwareId": "3212038e3f2f8791"
}
```

---

## API Endpoints Reference

All endpoints are under `https://digitalomni.navyfederal.org`.

### Authentication

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/auth/config/preauth` | Pre-auth configuration |
| `POST` | `/api/auth/mobile/authn` | Username + password login |
| `GET` | `/api/auth/tfa/options` | MFA phone options |
| `POST` | `/api/auth/tfa/challenge/otp` | Request SMS OTP |
| `POST` | `/api/auth/tfa/challenge/verification` | Verify OTP |
| `GET` | `/api/auth/esi/activation` | Token rotation (call 3×) |
| `POST` | `/api/auth/tfa/decision` | Risk assessment decision |
| `GET` | `/api/auth/status` | Session status check |
| `GET` | `/api/auth/refresh` | Refresh Bearer token |
| `GET` | `/api/auth/logout` | Invalidate session |

### Accounts

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/arrangement-manager/client-api/v2/arrangement-views/account-overview` | All accounts + balances |
| `GET` | `/api/arrangement-manager/client-api/v2/arrangements/{id}` | Single account detail |
| `GET` | `/api/account-management-service/client-api/v1/pod/beneficiaries/{id}` | Beneficiaries |

### Transactions

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/transaction-manager/client-api/v2/transactions?arrangementId={id}&from={n}&size={n}` | Paginated transactions |

### Cards

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/cards-presentation-service/client-api/v2/rewards/{id}` | Card rewards/cash-back |

### User & Permissions

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/user-manager/client-api/v2/users/me` | Member profile |
| `GET` | `/api/access-control/client-api/v3/accessgroups/user-context/service-agreements` | Service agreements |
| `GET` | `/api/access-control/client-api/v3/accessgroups/users/permissions/summary` | Permission summary |

### Content & Messaging

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/message-manager/client-api/v1/messages/indicator` | Unread message count |
| `GET` | `/api/content-manager/client-api/v1/mobile-tiles` | Home screen tile config |
| `GET` | `/api/content-manager/client-api/v1/last-modified` | Content cache check |
| `POST` | `/api/member-insights-service/client-api/v1/insights-offers` | Personalised offers |
