"""
Navy Federal Credit Union API client.

This module reverse-engineers the NFCU mobile app API (Android v2026.2.1).
The original node-nfcu project (https://github.com/tjhorner/node-nfcu) targeted
the now-tombstoned ``mservices.navyfcu.org`` endpoint.  This rewrite targets the
current Backbase-based microservices API at ``digitalomni.navyfederal.org``.

Reverse-engineering method
  Traffic was captured with mitmproxy (see ``intercept/start.sh``) against a
  Pixel 2 emulator running Android 14.  All endpoints, headers, and request
  bodies documented here were observed in live traffic captures on 2026-02-27.

Authentication flow (five steps)
  1. ``POST /api/auth/mobile/authn``
     Send username, password, and device fingerprint.  Server returns Bearer
     token 1 in the ``authorization`` response header.

  2. ``GET /api/auth/tfa/options``
     Fetch the list of phone numbers eligible for SMS OTP.

  3. ``POST /api/auth/tfa/challenge/otp``
     Request an OTP be sent to the chosen phone number.

  4. ``POST /api/auth/tfa/challenge/verification``
     Submit the OTP the user receives.  Server returns Bearer token 2.

  5. ``GET /api/auth/esi/activation`` (called up to 3 times)
     The third call returns Bearer token 3 in its ``authorization`` header.
     This is the token used for all subsequent API calls.

  Optional: ``POST /api/auth/tfa/decision``
     Completes risk assessment.  ``eventId`` is embedded inside the encrypted
     Bearer JWT (JWE, alg:dir enc:A128CBC-HS256) and requires the server's
     symmetric key to extract.  Passing ``eventId=None`` may be accepted.

Required headers (all authenticated requests)
  authorization       Bearer <token>
  x-xsrf-token        Must match the ``XSRF-TOKEN`` cookie value
  x-nf-profile-tag    32-char hex string; changes after OTP verification
  x-nf-device-metadata  Base64-encoded JSON of device info (see _device_metadata_header)
  cid                 "Mobile"
  platform            "AND"
  appversion          "2026.2.1"
  user-agent          "NavyFederal/2026.2.1 (Android 14)"
  content-type        "application/json"

Device fingerprint
  See ``nfcu/fingerprint.py`` for a full explanation of the ``_v02`` format,
  XOR obfuscation, base64 encoding, and the embedded RSA-2048 ``mfec`` signature.
"""
from __future__ import annotations

import base64
import json
from typing import Any

import requests

from nfcu import fingerprint as _fp
from nfcu.exceptions import (
    NFCUAPIError,
    NFCUAuthError,
    NFCUMFAError,
    NFCURateLimitError,
    NFCUSessionExpiredError,
)

# ── API constants ─────────────────────────────────────────────────────────────

_BASE_URL = "https://digitalomni.navyfederal.org"

# App version string observed in live traffic (Feb 2026).
# Update when NFCU releases a new app version.
_APP_VERSION = "2026.2.1"

# Android version running on the intercepted device.
_ANDROID_VERSION = "14"

# User-Agent header as sent by the NFCU Android app.
_USER_AGENT = f"NavyFederal/{_APP_VERSION} (Android {_ANDROID_VERSION})"

# Timeout in seconds for every HTTP request.
_REQUEST_TIMEOUT = 30

# Number of times to poll /esi/activation before giving up.
_ESI_ACTIVATION_MAX_TRIES = 3


# ── NFCU client ───────────────────────────────────────────────────────────────

class NFCU:  # pylint: disable=too-many-instance-attributes
    """Programmatic client for the Navy Federal Credit Union mobile API.

    Usage::

        client = NFCU("m0rissette", "s3cr3t")
        options = client.login()            # returns list of MFA phone options
        client.request_otp(options[0]["phoneId"])
        client.submit_mfa(input("OTP: "))  # blocks until you enter the code
        accounts = client.get_accounts()

    Args:
        username: NFCU online username (migrated from access number).
        password: Account password.
        device_fingerprint: ``_v02``-prefixed fingerprint string.  Defaults to
            a fingerprint captured from the emulator during traffic analysis.
            For production use, capture a fresh fingerprint from a real device
            using ``intercept/start.sh``.
        device_metadata: Dict of device info included in the
            ``x-nf-device-metadata`` header.  Defaults to emulator values.
    """

    def __init__(
        self,
        username: str,
        password: str,
        device_fingerprint: str = _fp.EMULATOR_FINGERPRINT,
        device_metadata: dict[str, Any] | None = None,
    ) -> None:
        self.username = username
        self.password = password
        self._device_fingerprint = device_fingerprint
        # Device metadata is sent as base64-encoded JSON in every request.
        self._device_metadata: dict[str, Any] = device_metadata or {
            "name": "Google",
            "model": "sdk_gphone64_arm64",
            "platform": "AND",
            "multitask": True,
            "systemName": "Android",
            "systemVersion": _ANDROID_VERSION,
            "screenSize": "2209x1080",
            "language": "en",
            "ipAddress": "10.0.2.15",
            "hardwareId": "3212038e3f2f8791",
        }

        # ── Auth state (populated progressively by login / submit_mfa) ─────
        # Bearer token extracted from `authorization` response headers.
        self._token: str | None = None
        # XSRF-TOKEN cookie value; must be echo'd back in x-xsrf-token header.
        self._xsrf_token: str | None = None
        # 32-char hex value from x-nf-profile-tag response headers; changes
        # after OTP verification completes.
        self._profile_tag: str | None = None
        # phoneId of the first MFA option; stored so request_otp() works
        # without requiring the caller to pass it explicitly.
        self._phone_id: str | None = None

        # Persistent session re-uses the same TCP connection and cookie jar.
        self._session = requests.Session()

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _device_metadata_header(self) -> str:
        """Return the x-nf-device-metadata header value (base64 JSON).

        The header carries a small JSON blob of device properties.  The server
        uses it to correlate the request with the device fingerprint and for
        analytics/fraud scoring.
        """
        return base64.b64encode(
            json.dumps(self._device_metadata, separators=(",", ":")).encode()
        ).decode("ascii")

    def _headers(self) -> dict[str, str]:
        """Build the common request headers required by every API call.

        Token, XSRF, and profile-tag are included only when they have been
        populated by prior auth steps.
        """
        headers: dict[str, str] = {
            "cid": "Mobile",
            "platform": "AND",
            "appversion": _APP_VERSION,
            "user-agent": _USER_AGENT,
            "content-type": "application/json",
            "accept": "application/json, text/plain, */*",
            "x-nf-device-metadata": self._device_metadata_header(),
        }
        if self._token:
            headers["authorization"] = f"Bearer {self._token}"
        if self._xsrf_token:
            headers["x-xsrf-token"] = self._xsrf_token
        if self._profile_tag:
            headers["x-nf-profile-tag"] = self._profile_tag
        return headers

    def _update_auth_state(self, response: requests.Response) -> None:
        """Extract and persist auth tokens from a response if present.

        The API progressively rotates the Bearer token across auth steps.
        Each step that issues a new token returns it in the ``authorization``
        response header.  The XSRF token is set as a cookie and must be
        mirrored in the ``x-xsrf-token`` request header (double-submit pattern).
        """
        auth_header = response.headers.get("authorization", "")
        if auth_header.startswith("Bearer "):
            self._token = auth_header[len("Bearer "):]

        # The cookie jar is managed automatically by requests.Session.
        xsrf = self._session.cookies.get("XSRF-TOKEN")
        if xsrf:
            self._xsrf_token = xsrf

        profile_tag = response.headers.get("x-nf-profile-tag")
        if profile_tag:
            self._profile_tag = profile_tag

    def _request(
        self,
        method: str,
        path: str,
        *,
        json_body: dict | None = None,
        params: dict | None = None,
    ) -> requests.Response:
        """Make an authenticated HTTP request and return the response.

        Handles common error cases uniformly so individual methods stay clean.

        Args:
            method: HTTP verb ("GET", "POST", etc.).
            path: API path starting with ``/api/...``.
            json_body: Dict serialised as the JSON request body (POST only).
            params: URL query parameters (GET only).

        Returns:
            The :class:`requests.Response` object (status is already checked).

        Raises:
            NFCUAuthError: HTTP 401 – session not established or token invalid.
            NFCUSessionExpiredError: HTTP 401 after a token was already set.
            NFCURateLimitError: HTTP 429.
            NFCUAPIError: Any other non-2xx response.
        """
        url = _BASE_URL + path
        resp = self._session.request(
            method,
            url,
            headers=self._headers(),
            json=json_body,
            params=params,
            timeout=_REQUEST_TIMEOUT,
        )
        # Always refresh auth state in case the server rotated tokens.
        self._update_auth_state(resp)

        if resp.status_code == 401:
            if self._token:
                raise NFCUSessionExpiredError(
                    f"Session expired ({method} {path}): {resp.text[:200]}"
                )
            raise NFCUAuthError(
                f"Unauthorized ({method} {path}): {resp.text[:200]}"
            )
        if resp.status_code == 429:
            raise NFCURateLimitError(
                f"Rate limited ({method} {path})"
            )
        if not resp.ok:
            raise NFCUAPIError(
                f"HTTP {resp.status_code} from {method} {path}: {resp.text[:200]}",
                status_code=resp.status_code,
                body=resp.text,
            )
        return resp

    # ── Authentication flow ───────────────────────────────────────────────────

    def login(self) -> list[dict]:
        """Initiate login and retrieve MFA phone options.

        Sends credentials and the device fingerprint to the authn endpoint.
        If accepted, fetches the list of phone numbers eligible for SMS OTP.

        Returns:
            List of phone number dicts, each containing at least:
              - ``phoneNumber`` – masked number, e.g. ``"*7761"``
              - ``phoneType``   – ``"M"`` (mobile) or ``"H"`` (home)
              - ``phoneId``     – base64 token used to request an OTP

        Raises:
            NFCUAuthError: If credentials are rejected.

        Example::

            options = client.login()
            # options[0] == {"phoneNumber": "*7761", "phoneType": "M",
            #                "phoneId": "MDAwMDAwMDQ4..."}
        """
        # Step 1: Authenticate with username / password + device fingerprint.
        # The server returns Bearer token 1 in the `authorization` header.
        self._request(
            "POST",
            "/api/auth/mobile/authn",
            json_body={
                "username": self.username,
                "password": self.password,
                "deviceFingerprint": self._device_fingerprint,
            },
        )

        # Step 2: Fetch available MFA options (phone numbers for OTP delivery).
        tfa_resp = self._request("GET", "/api/auth/tfa/options")
        data = tfa_resp.json()
        phones: list[dict] = data.get("phoneNumbers", [])
        if phones:
            # Store the first option so request_otp() can be called with no args.
            self._phone_id = phones[0]["phoneId"]
        return phones

    def request_otp(self, phone_id: str | None = None) -> dict:
        """Request an SMS OTP be sent to the given phone.

        Must be called after :meth:`login`.

        Args:
            phone_id: ``phoneId`` from the :meth:`login` response.  Defaults
                to the first phone option returned during login.

        Returns:
            Dict containing ``expiration`` (seconds until OTP expires) and
            ``message`` (``"Success"`` on success).

        Raises:
            NFCUAuthError: If called before :meth:`login` and no default
                phone_id is available.
        """
        pid = phone_id or self._phone_id
        if not pid:
            raise NFCUAuthError(
                "No phone_id available; call login() first or pass phone_id explicitly"
            )
        # The server sends an SMS to the phone associated with phone_id.
        resp = self._request(
            "POST",
            "/api/auth/tfa/challenge/otp",
            json_body={
                "phoneId": pid,
                # deviceName is the last 4 digits of the phone number; extracted
                # from the phoneId token or set to a placeholder.
                "deviceName": pid[-4:] if len(pid) >= 4 else "7761",
                "otpType": "SMS",
                "workflow": "login",
            },
        )
        return resp.json()

    def submit_mfa(self, otp: str, remember_device: bool = False) -> dict:
        """Complete authentication by verifying the OTP code.

        Must be called after :meth:`request_otp`.  Internally handles the full
        post-OTP sequence: verification → ESI activation (token rotation) →
        TFA decision.

        Args:
            otp: 6-digit OTP received via SMS.
            remember_device: Whether to ask the server to remember this device
                so future logins skip MFA.  Only works with a physical device
                that has a screen-lock PIN set; emulators without TEE support
                will fail silently and the flag is ignored.

        Returns:
            Verification response dict (contains ``name`` and ``message``).

        Raises:
            NFCUMFAError: If the OTP is invalid or expired.
        """
        # Step 4: Submit OTP for verification.  Server returns Bearer token 2.
        try:
            verify_resp = self._request(
                "POST",
                "/api/auth/tfa/challenge/verification",
                json_body={
                    "tfaType": "OTP",
                    "otp": otp,
                    "workflow": "login",
                },
            )
        except NFCUAPIError as exc:
            raise NFCUMFAError(f"OTP verification failed: {exc}") from exc

        # Step 5: Poll ESI activation up to 3 times.
        # The third successful response carries Bearer token 3 in its
        # `authorization` header.  This is the session token used for all
        # subsequent banking API calls.
        for _ in range(_ESI_ACTIVATION_MAX_TRIES):
            esi_resp = self._request("GET", "/api/auth/esi/activation")
            # A new token in the response header means activation succeeded.
            if esi_resp.headers.get("authorization"):
                break  # token was captured by _update_auth_state()

        # Optional step: TFA decision (risk assessment).
        # The eventId is embedded inside the encrypted JWE Bearer token and
        # would require the server's symmetric key to decode.  Attempting with
        # eventId=None; some server versions accept the request without it.
        # Failure here is non-fatal; the session is already usable.
        try:
            self._request(
                "POST",
                "/api/auth/tfa/decision",
                json_body={
                    "eventId": None,
                    "denyRisk": True,
                    "rememberDevice": remember_device,
                },
            )
        except NFCUAPIError:
            pass  # Non-critical; account endpoints remain accessible.

        return verify_resp.json()

    # ── Account methods ───────────────────────────────────────────────────────

    def get_accounts(self) -> dict:
        """Return an overview of all accounts with balances.

        Returns:
            Raw JSON dict from the arrangement-manager account-overview
            endpoint.  Typical top-level keys: ``products``, ``totalBalance``.
            Each product entry contains the arrangement ID (UUID) required by
            other methods.

        Example::

            data = client.get_accounts()
            for product in data["products"]:
                print(product["name"], product["currentBalance"])
        """
        resp = self._request(
            "GET",
            "/api/arrangement-manager/client-api/v2/arrangement-views/account-overview",
        )
        return resp.json()

    def get_account(self, account_id: str) -> dict:
        """Return detailed information for a single account.

        Args:
            account_id: UUID of the account (``id`` field from
                :meth:`get_accounts`).

        Returns:
            Raw arrangement JSON dict.  Contains full account details including
            masked account number, available balance, interest rate, etc.

        Example::

            # Flagship Checking
            detail = client.get_account("0a2c476a-d3bd-4a7a-9e1e-dca25ab0060a")
        """
        resp = self._request(
            "GET",
            f"/api/arrangement-manager/client-api/v2/arrangements/{account_id}",
        )
        return resp.json()

    def get_transactions(
        self,
        account_id: str,
        from_: int = 0,
        size: int = 25,
    ) -> dict:
        """Return transactions for an account, newest first.

        Args:
            account_id: UUID of the account.
            from_: Zero-based offset for pagination (default 0).
            size: Number of transactions to return per page (default 25).

        Returns:
            Dict with ``transactionItems`` list and ``totalElements`` count.
            Each transaction contains: ``id``, ``bookingDate``,
            ``transactionAmountCurrency`` (amount + currency), ``description``,
            ``creditDebitIndicator``, ``runningBalance``, etc.

        Example::

            txns = client.get_transactions(account_id, from_=0, size=50)
            for t in txns["transactionItems"]:
                sign = "+" if t["creditDebitIndicator"] == "CRDT" else "-"
                print(sign, t["transactionAmountCurrency"]["amount"],
                      t["description"])
        """
        resp = self._request(
            "GET",
            "/api/transaction-manager/client-api/v2/transactions",
            params={
                "arrangementId": account_id,
                "from": from_,
                "size": size,
                "orderBy": "bookingDate",
                "direction": "DESC",
            },
        )
        return resp.json()

    def get_card_rewards(self, account_id: str) -> dict:
        """Return rewards/cash-back information for a credit card account.

        Args:
            account_id: UUID of the credit card arrangement.

        Returns:
            Raw JSON dict from the cards-presentation-service rewards endpoint.
            Contains current cash-back balance and pending rewards.

        Example::

            rewards = client.get_card_rewards("2e2d1d00-0a50-4fe2-85d5-fb3fb915c56c")
        """
        resp = self._request(
            "GET",
            f"/api/cards-presentation-service/client-api/v2/rewards/{account_id}",
        )
        return resp.json()

    def get_user(self) -> dict:
        """Return profile information for the authenticated user.

        Returns:
            Dict with user details: ``fullName``, ``email``,
            ``membershipStatus``, etc.

        Example::

            me = client.get_user()
            print(me["fullName"])
        """
        resp = self._request("GET", "/api/user-manager/client-api/v2/users/me")
        return resp.json()

    def get_messages_indicator(self) -> dict:
        """Return the unread secure-message count.

        Returns:
            Dict with ``unreadCount`` (int).
        """
        resp = self._request(
            "GET", "/api/message-manager/client-api/v1/messages/indicator"
        )
        return resp.json()

    def logout(self) -> None:
        """Invalidate the current session on the server.

        Clears all locally stored tokens after the server-side session is
        terminated.  The object should not be used after calling this method.
        """
        try:
            self._request("GET", "/api/auth/logout")
        except Exception:  # pylint: disable=broad-except
            pass  # Best-effort; local tokens are cleared regardless.
        finally:
            # Always clear tokens so the object is in a clean state.
            self._token = None
            self._xsrf_token = None
            self._profile_tag = None
            self._phone_id = None
