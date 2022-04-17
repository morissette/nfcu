[![Build Status](https://travis-ci.org/morissette/nfcu.svg?branch=master)](https://travis-ci.org/morissette/nfcu)
[![Coverage Status](https://coveralls.io/repos/github/morissette/nfcu/badge.svg?branch=master)](https://coveralls.io/github/morissette/nfcu?branch=master)

# Navy Federal
Navy Federal Credit Union Python Module

# Update
* 2022-04-17: Worked on reverse engineering the mobile app auhentication via mitmproxy and HTTP proxy setup on iPhone network. Saved all of the TLS flows still trying to determine if this method is viable as there appears to be a multitude of device registration steps through third parties. Will need to remove the app and start from scratch to get a better view.

### Based On
A simple interface to Navy Federal's closed API based on the node version here:

https://github.com/tjhorner/node-nfcu

### Sample Use
```python
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
        print(json.dumps(bank.get_account_summary()))
    else:
        print("Please configure .config/creds, see .config/creds-sample")
```
