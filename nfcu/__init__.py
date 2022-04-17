"""
Navy Federal Module
Fork of https://github.com/tjhorner/node-nfcu
"""
import json
import os
import requests

from nfcu.constants import RISK_JSON
from nfcu.exceptions import *


class NFCU:
    '''Navy Federal Class'''

    API_BASE = 'https://mservices.navyfcu.org/'
    DATE_FORMAT = 'YYYY-MM-DD'

    def __init__(self, access_number, password):
        '''Make NFCU object'''
        self.access_number = access_number
        self.password = password
        self._cookie = None
        self.login()

    @staticmethod
    def _get_headers():
        '''Get Headers for call'''
        headers = {
            'Accept': 'application/json; charset=UTF-8',
            # Imitate a Nexus 6P
            'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 6.0.1; Nexus 6P Build/MMB29M)',
            'Content-Type': 'application/json',
            'Host': 'mservices.navyfcu.org'
        }
        return headers

    def _get(self, endpoint):
        '''Wrapper for GETting requests with
        authentication

        :param endpoint: API URI
        '''
        cookie = self._cookie

        response = requests.get(
            self.API_BASE + endpoint,
            headers=self._get_headers(),
            cookies=cookie
        )
        if response.status_code == 200:
            return response.json()
        raise NFCUGetError(
            f'Received error from NGCU API: {response.content}, {response.status_code}'
        )

    def _post(self, endpoint, post_data):
        '''Wrapper for POSTing requests with
        authentication

        :param endpoint: API URI
        :param post_data: Post Data
        '''
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
            f'Received error from NFCU API: {response.content}, {response.status_code}'
        )

    def login(self):
        '''Login to NFCU

        :param access_number: NFCU Access Number
        :param password: NFCU password
        :param callback: Callback func
        '''
        response = self._post(
            'Authenticator/services/loginv3',
            {
                'appVersion': '6.0.1',
                'deviceModel': 'Nexus 6p',
                'osPlatform': 'AND',
                'osVersion': '6.0.1',
                'username': self.access_number,
                'password': self.password
            }
        )
        message = response.json()
        if message['loginv2']['status'] == 'SUCCESS':
            self._cookie = response.cookies
            self.submit_mfa()
            return
        raise NFCULoginError(
            f'Login error: {message}'
        )

    def submit_mfa(self):
        '''MFA to auth request'''
        try:
            data_file = os.path.abspath(
                os.path.join(
                    os.path.dirname(__file__),
                    'data/riskcheck.json'
                )
            )
            with open(data_file, encoding='utf8') as file_handle:
                payload = json.load(file_handle)
        except json.JSONDecodeError as error:
            print(error.msg)
            payload = json.dumps(RISK_JSON)

        response = self._post(
            'MFA/services/riskCheck',
            payload
        )
        message = response.json()

        if message['riskCheck']['status'] == 'SUCCESS':
            return
        raise NFCUMFAError(
            f'Unable to proceed: {message}'
        )

    def get_account_summary(self):
        '''Get summary of all of the logged-in
        user's accounts

        :param callback: Callback func
        '''
        response = self._get('NativeBanking/services/accountSummary')
        if response['accountSummary']['status'] == 'SUCCESS':
            return response
        raise NFCUSummaryError(
            f'Unable to get account summary: {response}'
        )
