"""
Navy Federal Module
Fork of https://github.com/tjhorner/node-nfcu
"""
from nfcu.exceptions import *

import json
import os
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
        self._cookie = None
        self.login()

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
        cookie = self._cookie

        response = requests.get(
            self.API_BASE + endpoint,
            headers=self._get_headers(),
            params=params,
            cookies=cookie
        )
        if response.status_code == 200:
            return response.json()
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
        cookie = self._cookie

        response = requests.post(
            self.API_BASE + endpoint,
            headers=self._get_headers(),
            data=json.dumps(post_data),
            cookies=cookie
        )
        if response.status_code == 200:
            return response
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
        message = response.json()
        if message['loginv2']['status'] == 'SUCCESS':
            self._cookie = response.cookies
            self.submit_mfa()
            return
        raise NFCULoginError(
            "Login error: {error}".format(
                error=message['loginv2']['errors'][0]['errorMsg']
            )
        )

    def submit_mfa(self):
        """
        MFA to auth request
        """
        data_file = os.path.abspath(
            os.path.join(
                os.path.dirname(__file__),
                "data/riskcheck.json"
            )
        )
        with open(data_file) as df:
            payload = json.load(df)

        response = self._post(
            "MFA/services/riskCheck",
            payload
        )
        message = response.json()

        if message['riskCheck']['status'] == 'SUCCESS':
            return
        raise NFCUMFAError(
            "Unable to Proceed: {error}".format(
                error=message['riskCheck']['errors'][0]['errorMsg']
            )
        )

    def get_account_summary(self):
        """
        Get summary of all of the logged-in
        user's accounts
        :param callback: Callback func
        """
        response = self._get("NativeBanking/services/accountSummary")
        if response['accountSummary']['status'] == 'SUCCESS':
            return response
        raise NFCUSummaryError(
            "Unable to get account summary: {error}".format(
                response['accountSummary']['errors'][0]['errorMsg']
            )
        )
