"""
Unit tests for the nfcu package.
All network calls are mocked — no live API required.
"""
import json
from unittest.mock import MagicMock, patch

import pytest
import requests

import nfcu
from nfcu.exceptions import (
    NFCUGetError,
    NFCULoginError,
    NFCUMFAError,
    NFCUPostError,
    NFCUSummaryError,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

USERNAME = "test_user"
PASSWORD = "test_pass"

LOGIN_SUCCESS = {"loginv3": {"status": "SUCCESS"}}
LOGIN_FAILED = {
    "loginv3": {
        "status": "FAILED",
        "errors": [{"errorCode": "000E", "errorMsg": "Bad credentials"}],
    }
}
MFA_SUCCESS = {"riskCheck": {"status": "SUCCESS"}}
MFA_FAILED = {"riskCheck": {"status": "FAILED"}}
ACCOUNT_SUMMARY_SUCCESS = {
    "accountSummary": {
        "status": "SUCCESS",
        "data": {
            "accountCategories": [
                {"totalBalance": 1000.00},
                {"totalBalance": 500.00},
            ]
        },
    }
}
ACCOUNT_SUMMARY_FAILED = {"accountSummary": {"status": "FAILED"}}


def _mock_response(status_code=200, json_body=None):
    """Build a mock requests.Response."""
    mock = MagicMock(spec=requests.Response)
    mock.status_code = status_code
    mock.json.return_value = json_body or {}
    mock.cookies = MagicMock()
    mock.content = json.dumps(json_body or {}).encode()
    return mock


# ---------------------------------------------------------------------------
# NFCU initialisation
# ---------------------------------------------------------------------------

class TestNFCUInit:
    def test_login_called_on_init(self):
        with patch.object(nfcu.NFCU, "login") as mock_login:
            client = nfcu.NFCU(USERNAME, PASSWORD)
        mock_login.assert_called_once()
        assert client.username == USERNAME
        assert client.password == PASSWORD
        assert client._cookie is None  # noqa: SLF001 – testing internal state

    def test_credentials_stored(self):
        with patch.object(nfcu.NFCU, "login"):
            client = nfcu.NFCU(USERNAME, PASSWORD)
        assert client.username == USERNAME
        assert client.password == PASSWORD


# ---------------------------------------------------------------------------
# login()
# ---------------------------------------------------------------------------

class TestLogin:
    def _make_client(self):
        """Return an NFCU client with login suppressed."""
        with patch.object(nfcu.NFCU, "login"):
            return nfcu.NFCU(USERNAME, PASSWORD)

    def test_login_success_stores_cookie_and_calls_mfa(self):
        client = self._make_client()
        mock_resp = _mock_response(200, LOGIN_SUCCESS)

        with patch.object(client, "_post", return_value=mock_resp), \
                patch.object(client, "submit_mfa") as mock_mfa:
            client.login()

        assert client._cookie is mock_resp.cookies  # noqa: SLF001
        mock_mfa.assert_called_once()

    def test_login_failed_status_raises(self):
        client = self._make_client()
        mock_resp = _mock_response(200, LOGIN_FAILED)

        with patch.object(client, "_post", return_value=mock_resp):
            with pytest.raises(NFCULoginError):
                client.login()

    def test_login_post_error_propagates(self):
        client = self._make_client()

        with patch.object(client, "_post", side_effect=NFCUPostError("boom")):
            with pytest.raises(NFCUPostError):
                client.login()


# ---------------------------------------------------------------------------
# submit_mfa()
# ---------------------------------------------------------------------------

class TestSubmitMFA:
    def _make_client(self):
        with patch.object(nfcu.NFCU, "login"):
            return nfcu.NFCU(USERNAME, PASSWORD)

    def test_mfa_success(self):
        client = self._make_client()
        mock_resp = _mock_response(200, MFA_SUCCESS)

        with patch.object(client, "_post", return_value=mock_resp):
            client.submit_mfa()  # should not raise

    def test_mfa_failed_status_raises(self):
        client = self._make_client()
        mock_resp = _mock_response(200, MFA_FAILED)

        with patch.object(client, "_post", return_value=mock_resp):
            with pytest.raises(NFCUMFAError):
                client.submit_mfa()

    def test_mfa_missing_json_file_raises(self, tmp_path, monkeypatch):
        import nfcu as nfcu_module
        monkeypatch.setattr(nfcu_module, "_RISK_JSON_PATH", tmp_path / "missing.json")
        client = self._make_client()

        with pytest.raises(FileNotFoundError):
            client.submit_mfa()


# ---------------------------------------------------------------------------
# get_account_summary()
# ---------------------------------------------------------------------------

class TestGetAccountSummary:
    def _make_client(self):
        with patch.object(nfcu.NFCU, "login"):
            return nfcu.NFCU(USERNAME, PASSWORD)

    def test_success_returns_response(self):
        client = self._make_client()

        with patch.object(client, "_get", return_value=ACCOUNT_SUMMARY_SUCCESS):
            result = client.get_account_summary()

        assert result == ACCOUNT_SUMMARY_SUCCESS

    def test_failed_status_raises(self):
        client = self._make_client()

        with patch.object(client, "_get", return_value=ACCOUNT_SUMMARY_FAILED):
            with pytest.raises(NFCUSummaryError):
                client.get_account_summary()


# ---------------------------------------------------------------------------
# _get() / _post() HTTP error handling
# ---------------------------------------------------------------------------

class TestHTTPWrappers:
    def _make_client(self):
        with patch.object(nfcu.NFCU, "login"):
            return nfcu.NFCU(USERNAME, PASSWORD)

    def test_get_non_200_raises_nfcu_get_error(self):
        client = self._make_client()

        with patch("nfcu.requests.get", return_value=_mock_response(401)):
            with pytest.raises(NFCUGetError):
                client._get("some/endpoint")  # noqa: SLF001

    def test_post_non_200_raises_nfcu_post_error(self):
        client = self._make_client()

        with patch("nfcu.requests.post", return_value=_mock_response(403)):
            with pytest.raises(NFCUPostError):
                client._post("some/endpoint", {})  # noqa: SLF001

    def test_get_200_returns_json(self):
        client = self._make_client()
        payload = {"key": "value"}

        with patch("nfcu.requests.get", return_value=_mock_response(200, payload)):
            result = client._get("some/endpoint")  # noqa: SLF001

        assert result == payload

    def test_post_200_returns_response(self):
        client = self._make_client()
        mock_resp = _mock_response(200, {"ok": True})

        with patch("nfcu.requests.post", return_value=mock_resp):
            result = client._post("some/endpoint", {})  # noqa: SLF001

        assert result is mock_resp
