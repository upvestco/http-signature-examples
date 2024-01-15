# Copyright © 2024 Upvest GmbH <support@upvest.co>

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at

#     http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


# Python Standard Library imports
from collections.abc import Callable
import datetime
from typing import Any
from urllib.parse import urlparse, urlunparse

# 3rd-party imports
import requests

# local imports
from .http_message_signatures import get_lower_case_headers, UpvestHttpMessageSigner


class AuthorisationError(Exception):
    """Raised when a request for an Authorisation token fails."""

    def __init__(self, response,
                 message="Request for an Authorisaton token failed"):
        self.response = response
        self.message = message
        super().__init__(self.message)


# The path for requesting an auth token.
UPVEST_AUTH_TOKEN_PATH: str = '/auth/token'


class UpvestRequestsAuth(requests.auth.AuthBase):
    """A `requests.auth` middleware which fully takes care of authenticating with the Upvest Investment API.

    It fetches auth tokens on demand, adds all Upvest-specific headers and creates HTTP message signatures.
    """
    def __init__(
        self,
        *,
        private_key_pem: bytes,
        private_key_passphrase: bytes,
        key_id: str,
        client_id: str,
        client_secret: str,
        scopes: list[str],
        signer: UpvestHttpMessageSigner | None = None,
        callback_auth_response: Callable[[requests.Response], Any] | None = None,
        callback_signature_input: Callable[[bytes], Any] | None = None,
        callback_request: Callable[[requests.PreparedRequest], Any] | None = None
    ):
        if signer is None:
            self.signer = UpvestHttpMessageSigner(
                private_key_pem=private_key_pem,
                private_key_passphrase=private_key_passphrase,
                key_id=key_id,
                client_id=client_id
            )
        else:
            self.signer = signer

        self.client_id = client_id
        self.client_secret = client_secret
        self.scopes = scopes
        self.auth_token = {}

        # initialise to a moment in the past, in order to trigger auth token acquisition on initial call
        self.auth_token_expiry = datetime.datetime.now() - datetime.timedelta(hours=1)

        # TODO make configurable?
        self.auth_token_expiry_buffer = 5

        # These 3 callbacks are for debugging, demonstration and for comparison with other implementations.
        if callback_auth_response is None:
            self.callback_auth_response = lambda _: None
        else:
            self.callback_auth_response = lambda res: callback_auth_response(res)

        if callback_signature_input is None:
            self.callback_signature_input = lambda _: None
        else:
            self.callback_signature_input = lambda signature_input: callback_signature_input(signature_input)

        if callback_request is None:
            self.callback_request = lambda _: None
        else:
            self.callback_request = lambda req: callback_request(req)

    def _derive_auth_token_url(self, url: str) -> str:
        """
        Extract the base URL from the request's URL and replace path
        with UPVEST_AUTH_TOKEN_PATH.
        """
        parts = urlparse(url)
        return urlunparse((parts.scheme, parts.netloc, UPVEST_AUTH_TOKEN_PATH, '', '', ''))

    def _get_fresh_auth_token(self, auth_token_url: str) -> dict[str, str | int]:
        """Send an additional request for an auth token."""
        response = requests.post(
            auth_token_url,
            headers={'content-type': 'application/x-www-form-urlencoded'},
            data={
                'client_id': self.client_id,
                'client_secret': self.client_secret,
                'grant_type': 'client_credentials',
                'scope': ' '.join(self.scopes)
            },
            auth=self  # I guess you could call this recursion?
        )
        # This callback is for debug and comparison purposes
        self.callback_auth_response(response)
        if response.status_code != 200:
            raise AuthorisationError(response)
        return response.json()

    def _get_authorization_header(self, url: str) -> dict[str, str]:
        """Takes care of `authorization` header, fetches auth token on demand."""
        auth_token_url = self._derive_auth_token_url(url)
        if url == auth_token_url:
            # We are currently fetching an auth token, do not recurse any deeper!
            # An auth token request is the only request type which does not require an
            # `authorization` header.
            return {}

        now = datetime.datetime.now()
        if self.auth_token_expiry <= now:
            self.auth_token = self._get_fresh_auth_token(auth_token_url)
            # Example how an auth token response looks like:
            # {
            #     'access_token': 'ory_at_Wc7c4[...]wHjL4',
            #     'expires_in': 1799,
            #     'scope': 'users:admin',
            #     'token_type': 'bearer'
            # }
            # TODO respect effective scopes, i.e. the ones which we got back from this call.
            expiry_duration = int(self.auth_token['expires_in']) - self.auth_token_expiry_buffer
            self.auth_token_expiry = now + datetime.timedelta(seconds=expiry_duration)
        access_token = self.auth_token['access_token']
        return {'authorization': f'Bearer {access_token}'}

    def __call__(self, request: requests.PreparedRequest, idempotency_key: str | None = None) -> requests.PreparedRequest:
        """Provide this middleware to the `requests` library.

        The extraneous `idempotency_key` parameter can be used through calling `UpvestRequestsAuth.with_idempotency_key()`.
        """
        method = request.method
        url = request.url
        headers_in = get_lower_case_headers(request.headers)
        body = request.body

        headers_added = self._get_authorization_header(url)

        method, url, headers_out, body, signature_input = self.signer.sign_request(
            method=method,
            url=url,
            headers_in=headers_in | headers_added,
            body=body,
            idempotency_key=idempotency_key
        )

        request.method = method
        request.url = url
        for k, v in (headers_out | headers_added).items():
            request.headers[k] = v
        request.body = body

        # These callbacks are for debug and comparison purposes
        self.callback_signature_input(signature_input)
        self.callback_request(request)

        return request

    def with_idempotency_key(self, idempotency_key: str) -> Callable[[requests.PreparedRequest], requests.PreparedRequest]:
        """Allow explicit per-request idempotency keys.

        Certain endpoints in the Upvest Investment API insist on idempotency keys
        to prevent duplicate actions in case of network interruptions etc.

        Your business logic dictates which 2 requests are considered idempotent.
        This middleware can not automate this concern for you, you have to
        manage those idempotency keys yourself.

        There is a utility function to generate new idemptency keys,
        `make_idempotency_key()`.

        And instead of giving an instance of this middleware directly as the
        `auth` argument for a call to `requests.post()`, you would give the return value of this function instead, like so:

        ```
        idempotency_key = make_idempotency_key()
        res = requests.post(url, json=payload, auth=upvest_auth_instance.with_idempotency_key(idempotency_key))
        ```

        (This example lacks any error handling to focus on what it wants to demonstrate.)
        """
        return lambda req: self.__call__(req, idempotency_key)
