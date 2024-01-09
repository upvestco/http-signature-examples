import base64
import json
import sys

import requests

import settings

from upvest_investment_api import (
    make_idempotency_key,
    has_requests_auth
)
if has_requests_auth:
    from upvest_investment_api import UpvestRequestsAuth
else:
    sys.exit("You need to install the upvest-investment-api Python package with the requests-auth extra, like so: `pip install upvest-investment-api[requests-auth]`")


def pretty_print_signature_input(signature_input):
    print('-----------BEGIN SIGNATURE INPUT PLAIN-----------')
    print(signature_input.decode())
    print('-----------END   SIGNATURE INPUT PLAIN-----------')
    print('-----------BEGIN SIGNATURE INPUT BASE64-----------')
    print(base64.b64encode(signature_input).decode())
    print('-----------END   SIGNATURE INPUT BASE64-----------')


def pretty_print_request(req):
    print('-----------BEGIN REQUEST-----------')
    print(f'{req.method} {req.url}')
    [print(f'{k}: {v}') for k, v in req.headers.items()]
    print()
    print(req.body)
    print('-----------END   REQUEST-----------')


def pretty_print_response(res):
    try:
        response_body = json.dumps(res.json(), indent=4)
    except requests.exceptions.JSONDecodeError:
        response_body = res.text
    print('-----------BEGIN RESPONSE-----------')
    print(f'{res.status_code} {res.reason}')
    [print(f'{k}: {v}') for k, v in res.headers.items()]
    print()
    print(response_body)
    print('-----------END   RESPONSE-----------')


def setup_upvest_auth():
    return UpvestRequestsAuth(
        private_key_pem=settings.UPVEST_API_HTTP_SIGN_PRIVATE_KEY,
        private_key_password_bytes=settings.UPVEST_API_HTTP_SIGN_PRIVATE_KEY_PASSPHRASE_BYTES,
        key_id=settings.UPVEST_API_KEY_ID,
        client_id=settings.UPVEST_API_CLIENT_ID,
        client_secret=settings.UPVEST_API_CLIENT_SECRET,
        scopes=settings.UPVEST_API_SCOPES,
        callback_auth_response=pretty_print_response,
        callback_signature_input=pretty_print_signature_input,
        callback_request=pretty_print_request
    )


def main():
    upvest_auth = setup_upvest_auth()

    params = {'limit': 2, 'offset': 0}
    res = requests.get(f'{settings.UPVEST_API_BASE_URL}/users', params=params, auth=upvest_auth)
    pretty_print_response(res)

    new_user = {
        'first_name': 'Marcel',
        'last_name': 'Schwarz',
        'email': 'marcel@example.com',
        'birth_date': '1992-06-16',
        'birth_city': 'Mannheim',
        'birth_country': 'DE',
        'nationalities': ['DE'],
        'address': {
            'address_line1': 'Unter den Linden',
            'address_line2': '12a',
            'postcode': '10117',
            'city': 'Berlin',
            'country': 'DE'
        },
        'terms_and_conditions': {
            'consent_document_id': '62814307-f14b-40af-bc66-5942a549a759',
            'confirmed_at': '2020-02-03T17:14:46Z'
        },
        'data_privacy_and_sharing_agreement': {
            'consent_document_id': 'dd42b6a9-d04d-4dd2-8c3b-36386eaa843a',
            'confirmed_at': '2021-02-03T17:14:46Z'
        },
        'fatca': {
            'status': False,
            'confirmed_at': '2020-02-03T17:14:46Z'
        }
    }
    idempotency_key = make_idempotency_key()
    res = requests.post(f'{settings.UPVEST_API_BASE_URL}/users', json=new_user, auth=upvest_auth.with_idempotency_key(idempotency_key))
    pretty_print_response(res)
    user_id = res.json()['id']

    res = requests.delete(f'{settings.UPVEST_API_BASE_URL}/users/{user_id}', auth=upvest_auth)
    pretty_print_response(res)


if __name__ == '__main__':
    main()
