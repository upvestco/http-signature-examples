#!/usr/bin/env python3

# To use this script you'll need to:
#
#   pip3 install cryptography
#   pip3 install requests


import datetime
import json
import sys
import uuid

import requests


import upvest.http as up_http
    


if __name__ == "__main__":
    if len(sys.argv) != 6:
        print("sign.py <PEM FILE> <PEM password> <Preshared Key ID> <Client ID> <Client Secret>\n")
        sys.exit(1)

    pem_file = sys.argv[1]
    pem_password = bytes(sys.argv[2], 'utf-8')
    preshared_key_id = sys.argv[3]
    client_id = sys.argv[4]
    client_secret = sys.argv[5]
    
    api = up_http.UpvestAPI("sandbox.upvest.co", pem_file, pem_password, preshared_key_id, client_id, client_secret, scopes=["users:admin"])
    resp = api.get("/users", params={"limit": 2})
    
    print(resp.json())

    


