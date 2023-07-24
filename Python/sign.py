#!/usr/bin/env python3

# This script is a minimal example using a UpvestAPI object defined in
# the ./upvest/http.py file in this project. The UpvestAPI class wraps
# up the HTTP Message signature generation, based on the credentials
# required as arguments to this script (a PEM file, a password for
# that PEM file, the preshared Key ID (so we know what Public key to
# validate your requests against!) and the Client ID and Client secret
# required for the authorisation requests.

# To use this script you'll need to:
#
#   pip3 install cryptography
#   pip3 install requests


import http.client as http_client
import json
import logging
import os
import sys

import upvest.http as up_http



# Setting the environment variable "DEBUG" to any value will cause
# extra debugging information to be ommitted from the HTTP connection.
if "DEBUG" in os.environ:
    http_client.HTTPConnection.debuglevel = 1
    logging.basicConfig()
    logging.getLogger().setLevel(logging.DEBUG)
    requests_log = logging.getLogger("requests.packages.urllib3")
    requests_log.setLevel(logging.DEBUG)
    requests_log.propagate = True



class APIError(Exception):
    "Raised when we get an unexpected response from the API"

    def __init__(self, response):
        self.message=f"Unexpected HTTP response: {response}," \
            + f"{response.reason}"
        self.response = response
        super().__init__(self.message)


def get_users(api, limit=100, offset=0):
    """get_users returns a limited list of users from a given offset.

    api
                An instance of the UpvestAPI class.
    
    limit
                (optional) the maximum number of users to return.

    offset
                (optional) the offset from which to list user.  You can use
                the combination of the limit and offset to chunk the
                user list into pages.

    """
    params = {"limit": limit, "offset": offset}
    
    resp = api.get("/users", params=params)
    print(f"Requested a list of 2 users, and got: {resp} {resp.reason}\n")
    if resp.status_code != 200:
        raise APIError(resp)
    return resp.json()

def create_user(api, user):
    """
    create_users creates a user in the Investment API and returns
    the details.

    api
                An instance of the UpvestAPI class.

    user
                A dictionary representing a User as described in the
                documentation here:
                https://docs.upvest.co/api/Users#create-a-user

    """

    resp = api.post("/users", json=user)
    print(f"POSTed a new user and got: {resp} {resp.reason}")
    if resp.status_code != 200:
        raise APIError(resp)
    return resp.json()


def delete_user(api, user_id):
    """
    delete_user deletes a user identified by the user_id.

    api
                An instance of the UpvestAPI class.

    user_id
                The id of the user you wish to delete.
    """
    resp = api.delete(f"/users/{user_id}")
    print(f"DELETED the user and got: {resp} {resp.reason}")
    if resp.status_code != 202:
        raise APIError(resp)
    return True
    

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

    # The HTTP Message Signing, and auth token handling is bundled up
    # in the UpvestAPI class, that's where you should focus your
    # attention if you need to implement this functionality from
    # scratch.
    api = up_http.UpvestAPI("sandbox.upvest.co",
                            pem_file,
                            pem_password,
                            preshared_key_id,
                            client_id,
                            client_secret,
                            scopes=["users:admin", "portfolios:admin"])

    # We could do something with these users, but for now it's enough
    # just to get them succesfully.
    users = get_users(api, limit=2)
    
    
    user = create_user(api, {
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
    })

    deleted = delete_user(api, user['id'])
        

