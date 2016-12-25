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
