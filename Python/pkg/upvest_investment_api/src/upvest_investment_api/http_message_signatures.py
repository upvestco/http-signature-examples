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
import base64
import datetime
from email.utils import formatdate
import hashlib
import json
from urllib.parse import urlparse, urlunparse
import uuid

# 3rd-party imports
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ec import ECDSA
from cryptography.hazmat.primitives.serialization import load_pem_private_key


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
    def __init__(self, *, private_key_pem: bytes, private_key_passphrase: bytes, key_id: str):
        self.private_key = load_pem_private_key(private_key_pem, private_key_passphrase)
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
        private_key_passphrase: bytes,
        key_id: str,
        client_id: str,
        signer: HttpMessageSigner | None = None
    ):
        self.client_id = client_id
        if signer is None:
            self.signer = HttpMessageSigner(
                private_key_pem=private_key_pem,
                private_key_passphrase=private_key_passphrase,
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


def make_idempotency_key() -> str:
    """Generate an idempotency key in UUID v4 format as required by the Upvest Investment API."""
    return str(uuid.uuid4())
