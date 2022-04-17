"""
Exceptions for NFCU Package
"""


class NFCUGetError(Exception):
    """
    Raised when receiving a non 200 status code
    during a GET request
    """


class NFCUPostError(Exception):
    """
    Raised when receiving a non 200 status code
    during a POST request
    """


class NFCULoginError(Exception):
    """
    Raised when receiving a error from API
    upon login attempt
    """


class NFCUMFAError(Exception):
    """
    Raised when MFA fails
    """


class NFCUSummaryError(Exception):
    """
    Raised when Account Summary returns
    failed
    """
