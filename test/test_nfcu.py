"""
Unit tests for the nfcu package.
All network calls are mocked — no live API required.

Test coverage:
  - nfcu.fingerprint   encode/decode roundtrip and helpers
  - NFCU constructor   defaults and credential storage
  - _headers()         token/xsrf/profile-tag injection
  - _update_auth_state() token extraction from response
  - _request()         HTTP error mapping (401/429/500)
  - login()            authn + tfa/options flow
  - request_otp()      challenge/otp flow
  - submit_mfa()       verification + ESI activation loop + tfa/decision
  - get_accounts()     arrangement-manager endpoint
  - get_account()      single arrangement endpoint
  - get_transactions() pagination query params
  - get_card_rewards() cards endpoint
  - get_user()         user-manager endpoint
  - logout()           session teardown
"""
import base64
import json
from unittest.mock import MagicMock, call, patch

import pytest
import requests

import nfcu
from nfcu import fingerprint as fp
from nfcu.exceptions import (
    NFCUAPIError,
    NFCUAuthError,
    NFCUMFAError,
    NFCURateLimitError,
    NFCUSessionExpiredError,
)

# ── Constants ─────────────────────────────────────────────────────────────────

USERNAME = "test_user"
PASSWORD = "test_pass"

# Minimal valid _v02 fingerprint (encodes 'fpdt=2' XOR'd with 0x55, base64'd)
_PLAIN = "fpdt=2"
_FP_MINIMAL = "X" * 4  # placeholder; replaced below after we can encode
_FP_MINIMAL = fp.encode(_PLAIN)

PHONE_OPTIONS = [
    {
        "phoneNumber": "*1234",
        "phoneType": "M",
        "phoneId": "cGhvbmUtaWQtcGxhY2Vob2xkZXI=",
    }
]

AUTHN_BODY = {"token": "token1"}
TFA_OPTIONS_BODY = {"phoneNumbers": PHONE_OPTIONS}
OTP_BODY = {"expiration": 360, "message": "Success"}
VERIFY_BODY = {"name": "TEST", "message": "Success", "token": "token2"}
ESI_BODY = {"activationCode": "abc", "acExpiry": "2026-01-01", "passcode": True}
DECISION_BODY = {"message": "Success"}
ACCOUNTS_BODY = {"products": [{"id": "uuid-1", "name": "Checking"}]}
ACCOUNT_DETAIL_BODY = {"id": "uuid-1", "name": "Checking", "currentBalance": 100.0}
TRANSACTIONS_BODY = {
    "totalElements": 2,
    "transactionItems": [{"id": "tx1"}, {"id": "tx2"}],
}
REWARDS_BODY = {"cashBackBalance": 12.34}
USER_BODY = {"fullName": "TEST USER", "email": "test@example.com"}


# ── Helpers ───────────────────────────────────────────────────────────────────

def _mock_resp(
    status_code: int = 200,
    json_body: dict | None = None,
    headers: dict | None = None,
    cookies: dict | None = None,
) -> MagicMock:
    """Build a mock requests.Response."""
    m = MagicMock(spec=requests.Response)
    m.status_code = status_code
    m.ok = status_code < 400
    m.json.return_value = json_body or {}
    m.text = json.dumps(json_body or {})
    m.headers = headers or {}
    # requests.Session has a .cookies CookieJar; mimic get() on it
    cookie_jar = MagicMock()
    cookie_jar.get = lambda name, default=None: (cookies or {}).get(name, default)
    m.cookies = cookie_jar
    return m


def _make_client(**kwargs) -> nfcu.NFCU:
    """Create an NFCU client without invoking the network."""
    return nfcu.NFCU(USERNAME, PASSWORD, **kwargs)


# ── nfcu.fingerprint ──────────────────────────────────────────────────────────

class TestFingerprint:
    def test_encode_decode_roundtrip(self):
        plaintext = "fpdt=2&mfos=Android&mfov=14&fpts=1234567890000"
        encoded = fp.encode(plaintext)
        assert encoded.startswith("_v02")
        assert fp.decode(encoded) == plaintext

    def test_encode_produces_base64(self):
        encoded = fp.encode("hello=world")
        # After stripping prefix, should be valid base64
        raw = encoded[4:]
        decoded_bytes = base64.b64decode(raw + "==")
        # XOR back with 0x55 to verify
        restored = bytes(b ^ 0x55 for b in decoded_bytes).decode("ascii")
        assert restored == "hello=world"

    def test_decode_wrong_prefix_raises(self):
        with pytest.raises(ValueError, match="Unknown fingerprint version"):
            fp.decode("_v01somedata")

    def test_decode_emulator_fingerprint(self):
        plain = fp.decode(fp.EMULATOR_FINGERPRINT)
        assert "mfos=Android" in plain
        assert "mfov=14" in plain
        assert "mfa_id=3212038e3f2f8791" in plain
        assert "mfappid=com.navyfederal.android" in plain
        assert "mfec=" in plain

    def test_build_params_includes_fpts_and_mfec(self):
        params = fp.build_params(
            fp.EMULATOR_DEVICE_PARAMS, fpts=9999999999000, mfec="sig=="
        )
        assert "fpts=9999999999000" in params
        assert params.endswith("mfec=sig==")
        assert "mfos=Android" in params

    def test_build_params_fpts_after_mfpv(self):
        params = fp.build_params(
            fp.EMULATOR_DEVICE_PARAMS, fpts=123, mfec="x"
        )
        idx_mfpv = params.index("mfpv=")
        idx_fpts = params.index("fpts=")
        assert idx_fpts > idx_mfpv


# ── NFCU constructor ──────────────────────────────────────────────────────────

class TestNFCUInit:
    def test_credentials_stored(self):
        client = _make_client()
        assert client.username == USERNAME
        assert client.password == PASSWORD

    def test_default_fingerprint(self):
        client = _make_client()
        assert client._device_fingerprint == fp.EMULATOR_FINGERPRINT  # noqa: SLF001

    def test_custom_fingerprint(self):
        custom = fp.encode("fpdt=2&mfos=iOS")
        client = _make_client(device_fingerprint=custom)
        assert client._device_fingerprint == custom  # noqa: SLF001

    def test_default_tokens_none(self):
        client = _make_client()
        assert client._token is None  # noqa: SLF001
        assert client._xsrf_token is None  # noqa: SLF001
        assert client._profile_tag is None  # noqa: SLF001

    def test_no_login_on_init(self):
        """Unlike the old API, __init__ must NOT call login()."""
        with patch.object(nfcu.NFCU, "login") as mock_login:
            _make_client()
        mock_login.assert_not_called()


# ── _headers() ───────────────────────────────────────────────────────────────

class TestHeaders:
    def test_base_headers_always_present(self):
        client = _make_client()
        h = client._headers()  # noqa: SLF001
        assert h["cid"] == "Mobile"
        assert h["platform"] == "AND"
        assert h["appversion"] == nfcu._APP_VERSION  # noqa: SLF001
        assert "user-agent" in h
        assert "content-type" in h
        assert "x-nf-device-metadata" in h

    def test_authorization_absent_when_no_token(self):
        client = _make_client()
        assert "authorization" not in client._headers()  # noqa: SLF001

    def test_authorization_present_when_token_set(self):
        client = _make_client()
        client._token = "abc123"  # noqa: SLF001
        assert client._headers()["authorization"] == "Bearer abc123"  # noqa: SLF001

    def test_xsrf_and_profile_tag_injected(self):
        client = _make_client()
        client._xsrf_token = "xsrf_val"  # noqa: SLF001
        client._profile_tag = "tag_val"  # noqa: SLF001
        h = client._headers()  # noqa: SLF001
        assert h["x-xsrf-token"] == "xsrf_val"
        assert h["x-nf-profile-tag"] == "tag_val"

    def test_device_metadata_is_valid_base64_json(self):
        client = _make_client()
        meta_b64 = client._headers()["x-nf-device-metadata"]  # noqa: SLF001
        decoded = json.loads(base64.b64decode(meta_b64))
        assert decoded["platform"] == "AND"
        assert "hardwareId" in decoded


# ── _update_auth_state() ─────────────────────────────────────────────────────

class TestUpdateAuthState:
    def test_extracts_bearer_token(self):
        client = _make_client()
        resp = _mock_resp(headers={"authorization": "Bearer newtoken"})
        client._update_auth_state(resp)  # noqa: SLF001
        assert client._token == "newtoken"  # noqa: SLF001

    def test_ignores_non_bearer_auth(self):
        client = _make_client()
        resp = _mock_resp(headers={"authorization": "Basic abc"})
        client._update_auth_state(resp)  # noqa: SLF001
        assert client._token is None  # noqa: SLF001

    def test_extracts_profile_tag(self):
        client = _make_client()
        resp = _mock_resp(headers={"x-nf-profile-tag": "abc123"})
        client._update_auth_state(resp)  # noqa: SLF001
        assert client._profile_tag == "abc123"  # noqa: SLF001


# ── _request() error handling ─────────────────────────────────────────────────

class TestRequest:
    def test_401_without_token_raises_auth_error(self):
        client = _make_client()
        with patch.object(client._session, "request", return_value=_mock_resp(401)):  # noqa: SLF001
            with pytest.raises(NFCUAuthError):
                client._request("GET", "/api/test")  # noqa: SLF001

    def test_401_with_token_raises_session_expired(self):
        client = _make_client()
        client._token = "oldtoken"  # noqa: SLF001
        with patch.object(client._session, "request", return_value=_mock_resp(401)):  # noqa: SLF001
            with pytest.raises(NFCUSessionExpiredError):
                client._request("GET", "/api/test")  # noqa: SLF001

    def test_429_raises_rate_limit(self):
        client = _make_client()
        with patch.object(client._session, "request", return_value=_mock_resp(429)):  # noqa: SLF001
            with pytest.raises(NFCURateLimitError):
                client._request("GET", "/api/test")  # noqa: SLF001

    def test_500_raises_api_error(self):
        client = _make_client()
        with patch.object(client._session, "request", return_value=_mock_resp(500)):  # noqa: SLF001
            with pytest.raises(NFCUAPIError) as exc:
                client._request("GET", "/api/test")  # noqa: SLF001
        assert exc.value.status_code == 500

    def test_200_returns_response(self):
        client = _make_client()
        resp = _mock_resp(200, {"ok": True})
        with patch.object(client._session, "request", return_value=resp):  # noqa: SLF001
            result = client._request("GET", "/api/test")  # noqa: SLF001
        assert result is resp


# ── login() ──────────────────────────────────────────────────────────────────

class TestLogin:
    def test_returns_phone_options(self):
        client = _make_client()
        authn_resp = _mock_resp(200, AUTHN_BODY)
        tfa_resp = _mock_resp(200, TFA_OPTIONS_BODY)

        with patch.object(client, "_request", side_effect=[authn_resp, tfa_resp]):
            phones = client.login()

        assert phones == PHONE_OPTIONS

    def test_stores_default_phone_id(self):
        client = _make_client()
        authn_resp = _mock_resp(200, AUTHN_BODY)
        tfa_resp = _mock_resp(200, TFA_OPTIONS_BODY)

        with patch.object(client, "_request", side_effect=[authn_resp, tfa_resp]):
            client.login()

        assert client._phone_id == PHONE_OPTIONS[0]["phoneId"]  # noqa: SLF001

    def test_authn_posts_credentials_and_fingerprint(self):
        client = _make_client()
        authn_resp = _mock_resp(200, AUTHN_BODY)
        tfa_resp = _mock_resp(200, TFA_OPTIONS_BODY)

        with patch.object(client, "_request", side_effect=[authn_resp, tfa_resp]) as mock_req:
            client.login()

        first_call = mock_req.call_args_list[0]
        assert first_call.args[0] == "POST"
        assert first_call.args[1] == "/api/auth/mobile/authn"
        body = first_call.kwargs["json_body"]
        assert body["username"] == USERNAME
        assert body["password"] == PASSWORD
        assert "deviceFingerprint" in body

    def test_empty_phone_list(self):
        client = _make_client()
        authn_resp = _mock_resp(200, AUTHN_BODY)
        tfa_resp = _mock_resp(200, {"phoneNumbers": []})

        with patch.object(client, "_request", side_effect=[authn_resp, tfa_resp]):
            phones = client.login()

        assert phones == []
        assert client._phone_id is None  # noqa: SLF001

    def test_auth_error_propagates(self):
        client = _make_client()
        with patch.object(client, "_request", side_effect=NFCUAuthError("bad creds")):
            with pytest.raises(NFCUAuthError):
                client.login()


# ── request_otp() ─────────────────────────────────────────────────────────────

class TestRequestOTP:
    def test_uses_stored_phone_id(self):
        client = _make_client()
        client._phone_id = PHONE_OPTIONS[0]["phoneId"]  # noqa: SLF001
        resp = _mock_resp(200, OTP_BODY)

        with patch.object(client, "_request", return_value=resp) as mock_req:
            result = client.request_otp()

        assert result == OTP_BODY
        body = mock_req.call_args.kwargs["json_body"]
        assert body["phoneId"] == PHONE_OPTIONS[0]["phoneId"]
        assert body["otpType"] == "SMS"

    def test_accepts_explicit_phone_id(self):
        client = _make_client()
        resp = _mock_resp(200, OTP_BODY)
        custom_phone_id = "CUSTOM=="

        with patch.object(client, "_request", return_value=resp) as mock_req:
            client.request_otp(phone_id=custom_phone_id)

        body = mock_req.call_args.kwargs["json_body"]
        assert body["phoneId"] == custom_phone_id

    def test_raises_without_phone_id(self):
        client = _make_client()
        with pytest.raises(NFCUAuthError, match="No phone_id"):
            client.request_otp()


# ── submit_mfa() ──────────────────────────────────────────────────────────────

class TestSubmitMFA:
    def _esi_resp(self, has_token: bool = False) -> MagicMock:
        """ESI activation response; 3rd call carries a new Bearer token."""
        h = {"authorization": "Bearer token3"} if has_token else {}
        return _mock_resp(200, ESI_BODY, headers=h)

    def test_calls_verification_and_esi_and_decision(self):
        client = _make_client()
        verify_resp = _mock_resp(200, VERIFY_BODY)
        esi1 = self._esi_resp(False)
        esi2 = self._esi_resp(False)
        esi3 = self._esi_resp(True)
        decision_resp = _mock_resp(200, DECISION_BODY)

        side_effects = [verify_resp, esi1, esi2, esi3, decision_resp]
        with patch.object(client, "_request", side_effect=side_effects) as mock_req:
            client.submit_mfa("123456")

        paths = [c.args[1] for c in mock_req.call_args_list]
        assert paths[0] == "/api/auth/tfa/challenge/verification"
        assert all(p == "/api/auth/esi/activation" for p in paths[1:4])
        assert paths[4] == "/api/auth/tfa/decision"

    def test_returns_verify_response(self):
        client = _make_client()
        verify_resp = _mock_resp(200, VERIFY_BODY)
        esi_resp = self._esi_resp(True)
        decision_resp = _mock_resp(200, DECISION_BODY)

        with patch.object(
            client, "_request",
            side_effect=[verify_resp, esi_resp, decision_resp]
        ):
            result = client.submit_mfa("123456")

        assert result == VERIFY_BODY

    def test_mfa_error_on_bad_otp(self):
        client = _make_client()
        with patch.object(
            client, "_request",
            side_effect=NFCUAPIError("bad OTP", status_code=400)
        ):
            with pytest.raises(NFCUMFAError):
                client.submit_mfa("000000")

    def test_decision_failure_is_non_fatal(self):
        """tfa/decision can fail without breaking the session."""
        client = _make_client()
        verify_resp = _mock_resp(200, VERIFY_BODY)
        esi_resp = self._esi_resp(True)
        # tfa/decision raises an API error
        decision_err = NFCUAPIError("decision failed", status_code=400)

        with patch.object(
            client, "_request",
            side_effect=[verify_resp, esi_resp, decision_err]
        ):
            result = client.submit_mfa("123456")  # should NOT raise

        assert result == VERIFY_BODY

    def test_verification_body_contains_otp(self):
        client = _make_client()
        verify_resp = _mock_resp(200, VERIFY_BODY)
        esi_resp = self._esi_resp(True)
        decision_resp = _mock_resp(200, DECISION_BODY)

        with patch.object(
            client, "_request",
            side_effect=[verify_resp, esi_resp, decision_resp]
        ) as mock_req:
            client.submit_mfa("741035")

        body = mock_req.call_args_list[0].kwargs["json_body"]
        assert body["otp"] == "741035"
        assert body["tfaType"] == "OTP"


# ── get_accounts() ────────────────────────────────────────────────────────────

class TestGetAccounts:
    def test_returns_accounts_data(self):
        client = _make_client()
        resp = _mock_resp(200, ACCOUNTS_BODY)

        with patch.object(client, "_request", return_value=resp):
            result = client.get_accounts()

        assert result == ACCOUNTS_BODY

    def test_calls_correct_endpoint(self):
        client = _make_client()
        resp = _mock_resp(200, ACCOUNTS_BODY)

        with patch.object(client, "_request", return_value=resp) as mock_req:
            client.get_accounts()

        assert mock_req.call_args.args[0] == "GET"
        assert "account-overview" in mock_req.call_args.args[1]


# ── get_account() ─────────────────────────────────────────────────────────────

class TestGetAccount:
    def test_calls_correct_endpoint_with_id(self):
        client = _make_client()
        account_id = "0a2c476a-d3bd-4a7a-9e1e-dca25ab0060a"
        resp = _mock_resp(200, ACCOUNT_DETAIL_BODY)

        with patch.object(client, "_request", return_value=resp) as mock_req:
            result = client.get_account(account_id)

        assert result == ACCOUNT_DETAIL_BODY
        path = mock_req.call_args.args[1]
        assert account_id in path
        assert "arrangements" in path


# ── get_transactions() ───────────────────────────────────────────────────────

class TestGetTransactions:
    def test_default_pagination(self):
        client = _make_client()
        resp = _mock_resp(200, TRANSACTIONS_BODY)
        account_id = "uuid-1"

        with patch.object(client, "_request", return_value=resp) as mock_req:
            client.get_transactions(account_id)

        params = mock_req.call_args.kwargs["params"]
        assert params["arrangementId"] == account_id
        assert params["from"] == 0
        assert params["size"] == 25

    def test_custom_pagination(self):
        client = _make_client()
        resp = _mock_resp(200, TRANSACTIONS_BODY)

        with patch.object(client, "_request", return_value=resp) as mock_req:
            client.get_transactions("uuid-1", from_=50, size=10)

        params = mock_req.call_args.kwargs["params"]
        assert params["from"] == 50
        assert params["size"] == 10

    def test_returns_transaction_data(self):
        client = _make_client()
        resp = _mock_resp(200, TRANSACTIONS_BODY)

        with patch.object(client, "_request", return_value=resp):
            result = client.get_transactions("uuid-1")

        assert result == TRANSACTIONS_BODY
        assert len(result["transactionItems"]) == 2


# ── get_card_rewards() ────────────────────────────────────────────────────────

class TestGetCardRewards:
    def test_calls_correct_endpoint(self):
        client = _make_client()
        card_id = "2e2d1d00-0a50-4fe2-85d5-fb3fb915c56c"
        resp = _mock_resp(200, REWARDS_BODY)

        with patch.object(client, "_request", return_value=resp) as mock_req:
            result = client.get_card_rewards(card_id)

        assert result == REWARDS_BODY
        path = mock_req.call_args.args[1]
        assert card_id in path
        assert "cards-presentation-service" in path


# ── get_user() ────────────────────────────────────────────────────────────────

class TestGetUser:
    def test_returns_user_data(self):
        client = _make_client()
        resp = _mock_resp(200, USER_BODY)

        with patch.object(client, "_request", return_value=resp):
            result = client.get_user()

        assert result == USER_BODY

    def test_calls_user_manager_endpoint(self):
        client = _make_client()
        resp = _mock_resp(200, USER_BODY)

        with patch.object(client, "_request", return_value=resp) as mock_req:
            client.get_user()

        assert "user-manager" in mock_req.call_args.args[1]


# ── logout() ──────────────────────────────────────────────────────────────────

class TestLogout:
    def test_clears_all_tokens(self):
        client = _make_client()
        client._token = "tok"  # noqa: SLF001
        client._xsrf_token = "xsrf"  # noqa: SLF001
        client._profile_tag = "tag"  # noqa: SLF001
        client._phone_id = "pid"  # noqa: SLF001

        with patch.object(client, "_request", return_value=_mock_resp(200)):
            client.logout()

        assert client._token is None  # noqa: SLF001
        assert client._xsrf_token is None  # noqa: SLF001
        assert client._profile_tag is None  # noqa: SLF001
        assert client._phone_id is None  # noqa: SLF001

    def test_clears_tokens_even_on_request_failure(self):
        """Tokens should be cleared even if the logout request itself fails."""
        client = _make_client()
        client._token = "tok"  # noqa: SLF001

        with patch.object(
            client, "_request",
            side_effect=NFCUAPIError("logout failed", 500)
        ):
            client.logout()  # should NOT raise

        assert client._token is None  # noqa: SLF001

    def test_calls_logout_endpoint(self):
        client = _make_client()
        with patch.object(client, "_request", return_value=_mock_resp(200)) as mock_req:
            client.logout()

        assert mock_req.call_args.args[1] == "/api/auth/logout"
