"""
Exceptions for the NFCU package.
"""


# ── Legacy exceptions (kept for backwards compatibility) ──────────────────────

class NFCUGetError(Exception):
    """Raised when a GET request returns a non-2xx status code."""


class NFCUPostError(Exception):
    """Raised when a POST request returns a non-2xx status code."""


class NFCULoginError(Exception):
    """Raised when the server rejects the login credentials."""


class NFCUMFAError(Exception):
    """Raised when MFA verification fails (wrong OTP, expired code, etc.)."""


class NFCUSummaryError(Exception):
    """Raised when the account summary endpoint returns a failure status."""


# ── New exceptions ────────────────────────────────────────────────────────────

class NFCUAuthError(Exception):
    """Raised when authentication fails due to invalid credentials or session."""


class NFCUSessionExpiredError(NFCUAuthError):
    """Raised when the Bearer token has expired and cannot be refreshed."""


class NFCURateLimitError(Exception):
    """Raised when the API returns HTTP 429 (Too Many Requests)."""


class NFCUAPIError(Exception):
    """Raised for unexpected non-2xx API responses not covered by other types.

    Attributes:
        status_code: HTTP status code returned by the server.
        body: Raw response body text (may be empty).
    """

    def __init__(self, message: str, status_code: int = 0, body: str = "") -> None:
        super().__init__(message)
        self.status_code = status_code
        self.body = body
