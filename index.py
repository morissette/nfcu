"""
Entrypoint for NFCU
"""
from json.decoder import JSONDecodeError
import json
import nfcu

if __name__ == "__main__":

    try:
        with open('.config/creds') as df:
            creds = json.load(df)
        access_number = creds.get('access_number')
        password = creds.get('password')
    except JSONDecodeError as e:
        access_number, password = None, None

    if access_number and password:
        bank = nfcu.NFCU(access_number, password)
        bank.login()
    else:
        print("Please configure .config/creds, see .config/creds-sample")
