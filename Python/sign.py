#!/usr/bin/env python3

# To use this script you'll need to:
#
#   pip3 install cryptography
#   pip3 install requests


import json
import os
import sys

import upvest.http as up_http

import logging
import http.client as http_client

# Setting the environment variable "DEBUG" to any value will cause extra debugging information to be ommitted from the HTTP connection.
if "DEBUG" in os.environ:
    http_client.HTTPConnection.debuglevel = 1
    logging.basicConfig()
    logging.getLogger().setLevel(logging.DEBUG)
    requests_log = logging.getLogger("requests.packages.urllib3")
    requests_log.setLevel(logging.DEBUG)
    requests_log.propagate = True


# This script is a minimal example using a UpvestAPI object defined in
# the ./upvest/http.py file in this project. The UpvestAPI class wraps
# up the HTTP Message signature generation, based on the credentials
# required as arguments to this script (a PEM file, a password for
# that PEM file, the preshared Key ID (so we know what Public key to
# validate your requests against!) and the Client ID and Client secret
# required for the authorisation requests.

if __name__ == "__main__":
    if len(sys.argv) != 6:
        print("sign.py <PEM FILE> <PEM password> <Preshared Key ID> "
              "<Client ID> <Client Secret>\n")
        sys.exit(1)

    pem_file = sys.argv[1]
    pem_password = bytes(sys.argv[2], 'utf-8')
    preshared_key_id = sys.argv[3]
    client_id = sys.argv[4]
    client_secret = sys.argv[5]
    
    api = up_http.UpvestAPI("sandbox.upvest.co", pem_file, pem_password,
                            preshared_key_id, client_id, client_secret,
                            scopes=["users:admin"])
    resp = api.get("/users", params={"limit": 2})
    
    print(f"Requested a list of 2 users, and got: {resp} {resp.reason}\n")
    print(f"JSON output: \n {json.dumps(resp.json(), indent=2)}\n")

    data = {
        "first_name": "Marcel",
        "last_name": "Schwarz",
        "email": "marcel@example.com",
        "birth_date": "1992-06-16",
        "birth_city": "Mannheim",
        "birth_country": "DE",
        "nationalities": ["DE"],
        "address": {
            "address_line1": "Unter den Linden",
            "address_line2": "12a",
            "postcode": "10117",
            "city": "Berlin",
            "country": "DE"
        },
        "terms_and_conditions": {
            "consent_document_id": "62814307-f14b-40af-bc66-5942a549a759",
            "confirmed_at": "2020-02-03T17:14:46Z"
        },
        "data_privacy_and_sharing_agreement": {
            "consent_document_id": "dd42b6a9-d04d-4dd2-8c3b-36386eaa843a",
            "confirmed_at": "2021-02-03T17:14:46Z"
        },
        "fatca": {
            "status": False,
            "confirmed_at": "2020-02-03T17:14:46Z"
        }
    }
    

    resp = api.post("/users", json=data)
    print(f"POSTed a new user and got: {resp} {resp.reason}")

    


