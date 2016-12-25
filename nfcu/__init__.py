"""
Navy Federal Module
Fork of https://github.com/tjhorner/node-nfcu
"""

class NFCU(object):
    """
    Navy Federal Class
    """

    def __init__(self):
        """
        Constructor method
        """
        pass

    def _get_headers(self, extra=None):
        """
        Get Headers for call
        :param extra: Extra headers
        """
        pass

    def _get(self, endpoint, callback, params={}):
        """
        Wrapper for GETting requests with
        authentication
        :param endpoint: API URI
        :param callback: Callback func
        :param params: Optional extra params
        """
        pass

    def _post(self, endpoint, post_data, callback):
        """
        Wrapper for POSTing requests with
        authentication
        :param endpoint: API URI
        :param post_data: Post Data
        :param callback: Callback func
        """
        pass

    def login(self, access_number, password, callback):
        """
        Login to NFCU
        :param access_number: NFCU Access Number
        :param password: NFCU password
        :param callback: Callback func
        """
        pass

    def get_post_auth_config(self, callback):
        """
        Bunch of configuration info after
        authentication
        :param callback: Callback func
        """
        pass

    def get_member_summary(self, callback):
        """
        Get summary of the logged-in user
        :param callback: Callback func
        """
        pass

    def get_account_summary(self, callback):
        """
        Get summary of all of the logged-in
        user's accounts
        :param callback: Callback func
        """
        pass

    def get_account_details(self, account_id, callback):
        """
        Get specific account details for a
        given account ID
        :param account_id: Account ID
        :param callback: Callback func
        """
        pass
