"""
Navy Federal Module
Fork of https://github.com/tjhorner/node-nfcu
"""
from __future__ import annotations

import json
from pathlib import Path

import requests

from nfcu.exceptions import (
    NFCUGetError,
    NFCULoginError,
    NFCUMFAError,
    NFCUPostError,
    NFCUSummaryError,
)

_API_BASE = "https://mservices.navyfcu.org/"

_HEADERS = {
    "Accept": "application/json; charset=UTF-8",
    # Imitate a Nexus 6P running Android 6.0.1
    "User-Agent": (
        "Dalvik/2.1.0 (Linux; U; Android 6.0.1; Nexus 6P Build/MMB29M)"
    ),
    "Content-Type": "application/json",
    "Host": "mservices.navyfcu.org",
}

_RISK_JSON_PATH = Path(__file__).parent / "data" / "riskcheck.json"
_REQUEST_TIMEOUT = 30


class NFCU:
    """Navy Federal Credit Union API client."""

    def __init__(self, username: str, password: str) -> None:
        self.username = username
        self.password = password
        self._cookie: requests.cookies.RequestsCookieJar | None = None
        self.login()

    def _get(self, endpoint: str) -> dict:
        response = requests.get(
            _API_BASE + endpoint,
            headers=_HEADERS,
            cookies=self._cookie,
            timeout=_REQUEST_TIMEOUT,
        )
        if response.status_code == 200:
            return response.json()
        raise NFCUGetError(
            f"GET {endpoint} returned {response.status_code}: "
            f"{response.content}"
        )

    def _post(self, endpoint: str, post_data: dict) -> requests.Response:
        response = requests.post(
            _API_BASE + endpoint,
            headers=_HEADERS,
            data=json.dumps(post_data),
            cookies=self._cookie,
            timeout=_REQUEST_TIMEOUT,
        )
        if response.status_code == 200:
            return response
        raise NFCUPostError(
            f"POST {endpoint} returned {response.status_code}: "
            f"{response.content}"
        )

    def login(self) -> None:
        """Authenticate with NFCU."""
        response = self._post(
            "Authenticator/services/loginv3",
            {
                "appVersion": "6.0.1",
                "deviceModel": "Nexus 6p",
                "osPlatform": "AND",
                "osVersion": "6.0.1",
                "username": self.username,
                "password": self.password,
            },
        )
        message = response.json()
        if message["loginv3"]["status"] == "SUCCESS":
            self._cookie = response.cookies
            self.submit_mfa()
            return
        raise NFCULoginError(f"Login failed: {message}")

    def submit_mfa(self) -> None:
        """Submit device fingerprint to satisfy MFA."""
        payload = json.loads(_RISK_JSON_PATH.read_text(encoding="utf-8"))
        response = self._post("MFA/services/riskCheck", payload)
        message = response.json()
        if message["riskCheck"]["status"] == "SUCCESS":
            return
        raise NFCUMFAError(f"MFA failed: {message}")

    def get_account_summary(self) -> dict:
        """Return summary data for all accounts."""
        response = self._get("NativeBanking/services/accountSummary")
        if response["accountSummary"]["status"] == "SUCCESS":
            return response
        raise NFCUSummaryError(f"Account summary failed: {response}")
