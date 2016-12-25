class NFCUGetError(Exception):
    """
    Raised when receiving a non 200 status code
    during a GET request
    """
    pass

class NFCUPostError(Exception):
    """
    Raised when receiving a non 200 status code
    during a POST request
    """
    pass

class NFCULoginError(Exception):
    """
    Raised when receiving a error from API
    upon login attempt
    """
    pass

class NFCUMFAError(Exception):
    """
    Raised when MFA fails
    """
    pass

class NFCUSummaryError(Exception):
    """
    Raised when Account Summary returns
    failed
    """
    pass
