# Python Standard Library imports
import base64
from collections.abc import Callable
import datetime
from email.utils import formatdate
import hashlib
import json
from typing import Any
from urllib.parse import urlparse, urlunparse
import uuid

# 3rd-party imports
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ec import ECDSA
from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key
)
import requests


def get_lower_case_headers(headers: dict[str, str]) -> dict[str, str]:
    """Convert all dict keys to lower case."""
    return {k.lower(): v for k, v in headers.items()}


class CanonicalisationError(Exception):
    """Unable to standardise input values into the format required by the HTTP message signatures standard draft.

    Find details in the `message` field.
    Also @see https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-message-signatures-15
    """
    pass


# A sentinel value to allow using `now()` as the `created` timestamp by default.
# This allows us to use `None` to create a signature without a `created` timestamp.
# TODO elevate to sentinel type
CREATED_NOW_SENTINEL_VALUE = 'CREATED_NOW_SENTINEL_VALUE'


class HttpMessageSigner():
    """Creates a HTTP message signature.

    Only implements the parts of the HTTP message signatures standard draft which are needed for the
    Upvest Investment API, but tries to leave out any Upvest-specific additions.

    Also, tries to stay agnostic of any HTTP client libraries.
    """
    def __init__(self, *, private_key_pem: bytes, private_key_password_bytes: bytes, key_id: str):
        self.private_key = load_pem_private_key(private_key_pem, private_key_password_bytes)
        self.key_id = key_id

    def _get_content_digest_and_length_headers(self, body: bytes | None) -> dict[str, str]:
        """Creates `content-digest` and `content-length` headers if a request body is present.

        This ensures indirectly that the request body is covered by the signature.
        Also @see https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-digest-headers-10
        """

        # If there's no body (for example, in a GET request), then we
        # don't need to calculate a digest.
        if body is None or body == b'':
            return {}

        digest_bytes = hashlib.sha512(body).digest()
        digest_base64 = base64.b64encode(digest_bytes).decode()
        return {
            'content-digest': f'sha-512=:{digest_base64}:',
            'content-length': len(body),
        }

    def _get_nonce(self) -> str:
        """Generate a random string to be used as `nonce` value in the signature input.

        Nonce values protect against signature replay,
        @see https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-message-signatures-15#name-signature-replay
        """
        return str(uuid.uuid4())

    def _canonicalise_method(self, method: str | None) -> str | None:
        """Upper-cases the HTTP method, if given."""
        return str(method).upper() if method is not None else None

    def _canonicalise_url(self, url: str | None, url_parts_to_include: list[str]) -> tuple[str | None, dict[str, str | None]]:
        """Standardises the request URL and extracts the "derived components" from the URL.

        @see https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-message-signatures-15#name-derived-components
        """
        if url is None:
            if len(url_parts_to_include) > 0:
                raise CanonicalisationError(f'Unable to canonicalise ungiven URL while asked to sign these URL components: {url_parts_to_include}.')
            return None, {}

        parts = urlparse(url)

        scheme = parts.scheme.lower()
        default_port_suffix = {'http': ':80', 'https': ':443'}.get(scheme, '')
        authority = parts.netloc.lower().removesuffix(default_port_suffix)
        path = parts.path if parts.path != '' else '/'
        query = f'?{parts.query}' if parts.query != '' else None

        # TODO consider canonicalising (i.e. percent-encoding) non-ASCII path elements.
        # TODO consider implementing `"@request-target"`. It has rather complicated edge cases,
        # @see https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-message-signatures-15#name-request-target
        # TODO consider implementing `"@query-param";name="param"`,
        # @see https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-message-signatures-15#name-query-parameters

        reconstructed_query = query.removeprefix('?') if query is not None else ''
        canonicalised_url = urlunparse((scheme, authority, path, '', reconstructed_query, ''))

        url_parts = {
            '@target-uri': canonicalised_url,
            '@scheme': scheme,
            '@authority': authority,
            '@path': path,
            '@query': query,
        }

        return canonicalised_url, url_parts

    def _is_allowed_header(self, header_name: str) -> bool:
        """Stub for a header allowlist."""
        # TODO implement configurable allowlist
        # TODO exclude `Host` header, use `@authority` instead, @see https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-message-signatures-15#name-authority
        return True

    def _canonicalise_headers(self, headers: dict[str, str]) -> dict[str, str]:
        """Allowlists headers and lower-cases header names."""
        return {k: v for k, v in get_lower_case_headers(headers).items() if self._is_allowed_header(k)}

    def _canonicalise_body(self, body: bytes | str | dict | list | None) -> bytes | None:
        """Converts request body into bytes, if given."""
        if body is None:
            return None
        elif type(body) is bytes:
            return body
        elif type(body) is str:
            return body.encode("utf-8")
        elif type(body) in (dict, list):
            # TODO consider forcing 'content-type' header to 'application/json' in this case
            return json.dumps(body, allow_nan=False).encode("utf-8")
        else:
            raise CanonicalisationError(f'Unable to canonicalise body with type {type(body)}.')

    def _canonicalise_timestamps(self, created: str | int | float | None, expiry_duration: int | None) -> tuple[int | None, int | None, dict[str, str]]:
        """Takes care of `created` and `expires` timestamps and the `date` header."""
        if created is None:
            return None, None, {}
        elif created == CREATED_NOW_SENTINEL_VALUE:
            created = datetime.datetime.now(datetime.timezone.utc)
        elif type(created) in (int, float):
            # TODO consider setting `created_timestamp` directly in this case.
            created = datetime.datetime.fromtimestamp(int(created), tz=datetime.timezone.utc)
        elif type(created) is str:
            created = datetime.datetime.fromisoformat(created)
        else:
            raise CanonicalisationError(f'Unable to canonicalise "created" timestamp {created} with type {type(created)}.')

        created_timestamp = int(created.timestamp())

        date_header_value = formatdate(
            timeval=created_timestamp,
            localtime=False,
            usegmt=True
        )

        return (
            created_timestamp,
            None if expiry_duration is None else created_timestamp + int(expiry_duration),
            {'date': date_header_value}
        )

    def sign_request(
        self,
        *,
        method: str | None = None,
        url: str | None = None,
        url_parts_to_include: list[str] = ['@path', '@query'],
        headers_in: dict[str, str] = {},
        body: bytes | str | dict | list | None = None,
        created: str | int | float | None = CREATED_NOW_SENTINEL_VALUE,
        expiry_duration: int | None = 10,
        sig_id: str = 'sig1',
        alg: str | None = None,
        tag: str | None = None
    ) -> tuple[str | None, str | None, dict[str, str], bytes, bytes]:
        """Creates an HTTP message signature for a request."""
        method = self._canonicalise_method(method)
        url, url_parts = self._canonicalise_url(url, url_parts_to_include)
        headers_in = self._canonicalise_headers(headers_in)
        body = self._canonicalise_body(body)
        created_timestamp, expires_timestamp, date_header = self._canonicalise_timestamps(created, expiry_duration)

        signature_input_parts = {}

        if method is not None:
            signature_input_parts['@method'] = method

        for derived_component_key in url_parts_to_include:
            if derived_component_key in url_parts and url_parts[derived_component_key] is not None:
                signature_input_parts[derived_component_key] = url_parts[derived_component_key]

        headers_out = date_header | self._get_content_digest_and_length_headers(body)

        for k, v in (headers_in | headers_out).items():
            signature_input_parts[k] = v

        quoted_component_key_list = ' '.join([f'"{k}"' for k in signature_input_parts.keys()])
        signature_param_parts = [
            f'({quoted_component_key_list})',
            f'keyid="{self.key_id}"',
            f'nonce="{self._get_nonce()}"',
        ]

        if created_timestamp is not None:
            # no double quotes because it's an integer
            signature_param_parts.append(f'created={created_timestamp}')

        if expires_timestamp is not None:
            # no double quotes because it's an integer
            signature_param_parts.append(f'expires={expires_timestamp}')

        if alg is not None:
            signature_param_parts.append(f'alg="{alg}"')

        if tag is not None:
            signature_param_parts.append(f'tag="{tag}"')

        signature_params = ';'.join(signature_param_parts)
        headers_out['signature-input'] = f'{sig_id}={signature_params}'
        signature_input_parts['@signature-params'] = signature_params
        signature_input = '\n'.join([f'"{k}": {v}' for k, v in signature_input_parts.items()]).encode('utf-8')

        signature = self.private_key.sign(signature_input, ECDSA(hashes.SHA512()))
        signature_base64 = base64.b64encode(signature).decode()

        headers_out['signature'] = f'{sig_id}=:{signature_base64}:'

        return method, url, headers_out, body, signature_input


# AFAICT these are the only values that the Upvest Investment API accepts for the `accept` header.
# TODO Combine with 'application/problem+json' after Upvest Investment API can
# handle that in an 'accept' header.
UPVEST_ACCEPTABLE_ACCEPT_HEADER_VALUES: list[str] = [
    'application/json',
    'application/pdf',
]


# If a header name starts with any of these prefixes, then that header is not to be included in the signature.
UPVEST_IGNORABLE_HEADER_PREFIXES: list[str] = [
    # INTERNAL NOTE: Copied from `ignoreHeadersWithPrefix` in */sign/domain.go
    'cf-',
    'cdn-',
    'cookie',
    'x-',
    'priority',
    'upvest-signature',
    'sec-',

    # Also exclude these, for reasons TBD.
    'user-agent',
    'accept-encoding',
    'connection',
]


def _has_ignorable_header_prefix(header_name: str) -> bool:
    """Decides whether a header is to be excluded from the signature."""
    return header_name.lower().startswith(tuple(UPVEST_IGNORABLE_HEADER_PREFIXES))


def _filter_headers(headers: dict[str, str]) -> dict[str, str]:
    """Returns all headers which are to be included from the signature."""
    return {k: v for k, v in headers.items() if not _has_ignorable_header_prefix(k)}


class UpvestHttpMessageSigner():
    """Creates a HTTP message signature and adds (nearly) every Upvest-specific requirement.

    Adds a few Upvest-specific HTTP headers.

    Does *not* add auto-acquisition of an OAuth2 token,
    since that would require knowledge of an actual HTTP client library,
    which this abstraction level tries to avoid, still.

    *Also* tries to stay agnostic of any HTTP client libraries.
    """
    def __init__(
        self,
        *,
        private_key_pem: bytes,
        private_key_password_bytes: bytes,
        key_id: str,
        client_id: str,
        signer: HttpMessageSigner | None = None
    ):
        self.client_id = client_id
        if signer is None:
            self.signer = HttpMessageSigner(
                private_key_pem=private_key_pem,
                private_key_password_bytes=private_key_password_bytes,
                key_id=key_id
            )
        else:
            self.signer = signer

    def _canonicalise_accept_header(self, headers: dict[str, str]) -> dict[str, str]:
        """Forces the `accept` header to one of the values that the Upvest Investment API can handle."""
        if 'accept' not in headers or headers['accept'] not in UPVEST_ACCEPTABLE_ACCEPT_HEADER_VALUES:
            return {'accept': 'application/json'}
        return {}

    def sign_request(
        self,
        *,
        method: str | None = None,
        url: str | None = None,
        headers_in: dict[str, str] = {},
        body: bytes | str | dict | list | None = None,
        idempotency_key: str | None = None
    ) -> tuple[str | None, str | None, dict[str, str], bytes, bytes]:
        """Creates an HTTP message signature for a request and adds Upvest-specific headers."""
        headers_in = get_lower_case_headers(headers_in)
        headers_in = _filter_headers(headers_in)

        headers_added = self._canonicalise_accept_header(headers_in)
        headers_added |= {
            'upvest-api-version': '1',
            'upvest-client-id': self.client_id,
        }

        if idempotency_key is not None:
            headers_added |= {'idempotency-key': idempotency_key}

        method, url, headers_out, body, signature_input = self.signer.sign_request(
            method=method,
            url=url,
            headers_in=headers_in | headers_added,
            body=body
        )

        headers_out |= {'upvest-signature-version': '15'}

        return method, url, headers_added | headers_out, body, signature_input


class AuthorisationError(Exception):
    """Raised when a request for an Authorisation token fails."""

    def __init__(self, response,
                 message="Request for an Authorisaton token failed"):
        self.response = response
        self.message = message
        super().__init__(self.message)


# The path for requesting an auth token.
UPVEST_AUTH_TOKEN_PATH: str = '/auth/token'


def make_idempotency_key() -> str:
    """Generate an idempotency key in UUID v4 format as required by the Upvest Investment API."""
    return str(uuid.uuid4())


class UpvestRequestsAuth(requests.auth.AuthBase):
    """A `requests.auth` middleware which fully takes care of authenticating with the Upvest Investment API.

    It fetches auth tokens on demand, adds all Upvest-specific headers and creates HTTP message signatures.
    """
    def __init__(
        self,
        *,
        private_key_pem: bytes,
        private_key_password_bytes: bytes,
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
                private_key_password_bytes=private_key_password_bytes,
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
