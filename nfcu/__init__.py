"""
Navy Federal Module
Fork of https://github.com/tjhorner/node-nfcu
"""
from nfcu.exceptions import *

import json
import requests

class NFCU(object):
    """
    Navy Federal Class
    """

    API_BASE = "https://mservices.navyfcu.org/"
    DATE_FORMAT = "YYYY-MM-DD"

    def __init__(self, access_number, password):
        """
        Constructor method
        """
        self.access_number = access_number
        self.password = password

    def _get_headers(self, extra=None):
        """
        Get Headers for call
        :param extra: Extra headers
        """
        headers = {
            "Accept": "application/json; charset=UTF-8",
            "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 6.0.1; Nexus 6P Build/MMB29M)", # Imitate a Nexus 6P
            "Content-Type": "application/json",
            "Host": "mservices.navyfcu.org"
        }
        return headers

    def _get(self, endpoint, params={}):
        """
        Wrapper for GETting requests with
        authentication
        :param endpoint: API URI
        :param params: Optional extra params
        """
        response = requests.get(
            self.API_BASE + endpoint,
            headers=self._get_headers(),
            params=params
        )
        if response.status_code == 200:
            return response.json()
        else:
            raise NFCUGetError(
                "Received error from NFCU API: {text}, {code}".format(
                    text=response.content,
                    code=response.status_code
                )
            )

    def _post(self, endpoint, post_data):
        """
        Wrapper for POSTing requests with
        authentication
        :param endpoint: API URI
        :param post_data: Post Data
        """
        response = requests.post(
            self.API_BASE + endpoint,
            headers=self._get_headers(),
            data=json.dumps(post_data)
        )
        if response.status_code == 200:
            return response.json()
        else:
            raise NFCUPostError(
                "Received error from NFCU API: {text}, {code}".format(
                    text=response.content,
                    code=response.status_code
                )
            )

    def login(self):
        """
        Login to NFCU
        :param access_number: NFCU Access Number
        :param password: NFCU password
        :param callback: Callback func
        """
        response = self._post(
            "Authenticator/services/loginv2",
            {
                "appVersion": "6.0.1",
                "deviceModel": "Nexus 6p",
                "osPlatform": "AND",
                "osVersion": "6.0.1",
                "username": self.access_number,
                "password": self.password
            }
        )
        print(response)

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
