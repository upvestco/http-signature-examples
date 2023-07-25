# Standard library imports
from email.utils import formatdate
import base64
import datetime
import hashlib
import secrets
import urllib
import uuid

# 3rd party libraries
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ec import ECDSA
from cryptography.hazmat.primitives.serialization import \
    load_pem_private_key
import requests


class AuthorisationFailedError(Exception):
    "Raised when a request for an Authorisation token fails."

    def __init__(self, response,
                 message="Request for an Authorisaton token failed"):
        self.response = response
        self.message = message
        super().__init__(self.message)


class UpvestAPI():
    """
    UpvestAPI provides HTTP primitives (GET, POST, PUT, PATCH,
    DELETE) enhanced with the HTTP Message Signing required to
    authenticate with Upvest Investment API.
    """

    # we give a 5 second buffer to the token expiry time, so we
    # request a new token early and don't send requests with a token
    # that might expire.
    _token_expiry_buffer = 5

    # We always use HTTPS, so there's no need to have the consumer
    # pass this in.
    _protocol = "https"

    def __init__(self, host, pem_file_path, pem_password, preshared_key_id,
                 client_id, client_secret, scopes=[]):
        """
        Creates a new UpvestAPI object based on your PEM file and credentials.

        host
                The hostname you wish to make requests against,
                e.g. sandbox.upvest.co

        pem_file_path
                The filesystem path to your PEM file containing the private key
                from the keypair you generated.

        pem_password
                The password to decrypt the PEM file.

        preshared_key_id
                The key ID that identifies the keypair.  This needs to be
                communicated in requests in order for the server to identify
                the public key, you previously shared with Upvest, with which
                we will validate your HTTP requests.

        client_id
                The client id you use to identify yourself to Upvest.

        client_secret
                The secret that accompanies your client id in identifying you
                to Upvest.

        scopes
                A list of the oauth scopes you require to be assoctiated with
                the authorisation token that will be issued.  You can find the
                scope required for each request in the API reference section of
                our documetation: https://docs.upvest.co/api

        """

        self._host = host
        self._pk = self._read_private_key_from_pem(pem_file_path, pem_password)
        self._preshared_key_id = preshared_key_id
        self._client_id = client_id
        self._client_secret = client_secret
        self._scopes=scopes
        self._session = requests.Session()
        self._token = None
        self._token_expires = datetime.datetime.now()

    def _read_private_key_from_pem(self, pem_file, pem_password):
        with open(pem_file, 'rb') as fh:
            key = fh.read()
            decrypted_key = load_pem_private_key(key, pem_password)
        return decrypted_key

    def _make_url(self, path):
        return self._protocol + "://" + self._host + path

    def _add_digest(self, request):
        # If there's no body (for example, in a GET request), then we
        # don't need to calculate a digest. Note: this is mirrored in
        # the content keys we pass into the signature calculation as
        # well. If you try to include a digest that doesn't exist, you
        # will end up with an invalid signature.
        if request.body is not None:
            if type(request.body) is bytes:
                digest = hashlib.sha512(request.body).digest()
            else:
                digest = hashlib.sha512(request.body.encode("utf-8")).digest()
            request.headers["Content-Digest"] = "sha-512=:%s:" % \
                base64.b64encode(digest).decode()
        return request

    def _make_sig_key_names(self, content_keys):
        # Note: the " marks around the key names. This is an explicit requirment
        #       in version 15 of the message signature algorithm. When using
        #       the early v6 algorithm, Upvest requires that these
        #       double-quotation marks are *not* present.
        return ' '.join(['"' + key + '"' for key in content_keys])

    def _make_sig_params(self, created, content_keys):
        sig_key_names = self._make_sig_key_names(content_keys)
        created_timestamp = int(created.timestamp())
        expiry_timestamp = created_timestamp + 100
        nonce = secrets.token_hex(16)
        return f'({sig_key_names});' \
            f'keyid="{self._preshared_key_id}";' \
            f'created={created_timestamp};' \
            f'expires={expiry_timestamp};' \
            f'nonce="{nonce}"'

    def _make_signature_payload(self, request, created, content_keys):
        sig_params = self._make_sig_params(created, content_keys)
        sig_value = ""
        values = {key.lower(): value for key, value in request.headers.items()}
        values["@method"] = request.method
        parts = urllib.parse.urlparse(request.path_url)
        values["@path"] = parts.path
        # We only include the @query header if there's really a query string.
        # Adding headers without matching values would result in an invalid
        # signature.
        if parts.query:
            values["@query"] = "?" + parts.query

        # We only use the specified values.  Don't, for example, put all of your
        # headers into your signature.
        for key in content_keys:
            value = values[key]
            sig_value += f'"{key}": {value}\n'

        sig_value += f'"@signature-params": {sig_params}'
        sig_input = 'sig1=' + sig_params
        return sig_input, sig_value

    def _sign(self, request, path, created, content_keys=[]):
        sig_input, sig_value = self._make_signature_payload(
            request, created, content_keys)
        signature = base64.b64encode(
            self._pk.sign(sig_value.encode('utf-8'), ECDSA(hashes.SHA512())))
        request.headers["Signature"] = 'sig1=:%s:' % signature.decode()
        request.headers["Signature-Input"] = sig_input
        return request

    def _auth(self):
        # If we have a current token with plenty of time left before
        # it expires, we'll just use that, otherwise, request a new one.
        base_time = datetime.datetime.now()
        if self._token_expires > base_time + datetime.timedelta(
                self._token_expiry_buffer):
            return

        path = "/auth/token"
        url = self._make_url(path)
        created = datetime.datetime.now()

        req = requests.Request(
            "POST",
            url,
            headers={
                'Date': formatdate(timeval=created.timestamp(),
                                   localtime=False, usegmt=True),
                "Accept": "*/*",
                "upvest-client-id": self._client_id,
                "Content-Type": "application/x-www-form-urlencoded",
                "Upvest-Signature-Version": "15",
            },
            data={"client_id": self._client_id,
                  "client_secret": self._client_secret,
                  "grant_type": "client_credentials",
                  "scope": " ".join(self._scopes)}
        )
        prepped = req.prepare()
        req = self._add_digest(prepped)
        content_keys = ['accept', 'content-length', 'content-type',
                        'upvest-client-id', '@method', '@path',
                        'content-digest', 'date']

        req = self._sign(prepped, path, created, content_keys=content_keys)

        resp = self._session.send(prepped)
        if resp.status_code != 200:
            raise AuthorisationFailedError(resp)

        self._token = resp.json()
        self._token_expires = base_time + datetime.timedelta(
            seconds=int(self._token['expires_in']))

    def _gen_idempotency_key(self):
        # It's very important that idempotency keys follow the right format.
        # You want to transmit something that looks like:
        #       749d0a18-a45f-4acd-bb2c-e93112da0660
        return str(uuid.uuid4())


    def _request_without_payload(self, method, path, params=None):
        self._auth()
        # Note: These requests don't need Content-Length or Content-Digest in
        #       the content_keys.  These elements are both derived from the
        #       request body and thus
        content_keys = ['accept', 'content-type',
                        'upvest-client-id', '@method', '@path',
                        'date', 'authorization']

        if params:
            content_keys.append("@query")

        created = datetime.datetime.now()
        url = self._make_url(path)
        req = requests.Request(
            method,
            url,
            params=params,
            headers={
                'Date': formatdate(timeval=created.timestamp(),
                                   localtime=False, usegmt=True),
                "Accept": "application/json",
                "upvest-client-id": self._client_id,
                "authorization": "Bearer %s" % self._token["access_token"],
                "Content-Type": "application/json",
                "Upvest-Signature-Version": "15",
            })

        prepped = req.prepare()
        req = self._sign(prepped, path, created, content_keys=content_keys)
        return self._session.send(prepped)

    def _request_with_payload(self, method, path, json=None):
        self._auth()
        content_keys = ['accept',  'content-type',
                        'upvest-client-id', '@method', '@path',
                        'date', 'authorization', 'idempotency-key']
        # If there's a payload we'll need to use the content-length
        # and content-digest in our signature.
        if json:
            content_keys.append('content-length')
            content_keys.append('content-digest')

        created = datetime.datetime.now()
        url = self._make_url(path)

        # We should always provide an idempotency key when making requests that
        # change state. This avoids duplicate requests from being processed
        # when they shouldn't be. It's also required in the signature for POST
        # requests.
        idempotency_key = self._gen_idempotency_key()

        req = requests.Request(
            method,
            url,
            headers={
                'Date': formatdate(timeval=created.timestamp(),
                                   localtime=False, usegmt=True),
                "Accept": "application/json",
                "upvest-client-id": self._client_id,
                "authorization": "Bearer %s" % self._token["access_token"],
                "Content-Type": "application/json",
                "Upvest-Signature-Version": "15",
                "Idempotency-Key": idempotency_key,
            },
            json=json)

        prepped = req.prepare()
        # Again, we only need the digest if we have a payload.
        if json:
            req = self._add_digest(prepped)
        req = self._sign(req, path, created, content_keys=content_keys)
        return self._session.send(req)

    def get(self, path, params=None):
        """Get performs an HTTP GET request against the Upvest Investment API.

        path
                The path to the endpoint you wish to GET. This value should
                always begin with a leading '/'. e.g. /fees/collections

        params
                (optional) A dictionary of key/value pairs to be encoded in the
                query section of the URL.
        """
        return self._request_without_payload("GET", path, params=params)

    def post(self, path, json=None):
        """POST performs an HTTP POST request against the Upvest Investment API.

        path
                The path to the endpoint you wish to GET. This value should
                always begin with a leading '/'. e.g. /fees/collections

        json
                (optional) A JSON serializable Python object to send in the body
                of the Request.
        """
        return self._request_with_payload("POST", path, json=json)

    def patch(self, path, json=None):
        """PATCH performs an HTTP PATCH request against the Upvest Investment API.

        path
                The path to the endpoint you wish to GET. This value should
                always begin with a leading '/'. e.g. /fees/collections

        json
                (optional) A JSON serializable Python object to send in the body
                of the Request.
        """
        return self._request_with_payload("PATCH", path, json=json)

    def put(self, path, json=None):
        """PUT performs an HTTP PUT request against the Upvest Investment API.

        path
                The path to the endpoint you wish to GET. This value should
                always begin with a leading '/'. e.g. /fees/collections

        json
                (optional) A JSON serializable Python object to send in the body
                of the Request.
        """
        return self._request_with_payload("PUT", path, json=json)

    def delete(self, path, params=None):
        """
        Delete performs an HTTP DELETE request against the Upvest Investment
        API.

        path
                The path to the endpoint you wish to DELETE. This value should
                always begin with a leading '/'. e.g. /fees/collections

        params
                (optional) A dictionary of key/value pairs to be encoded in the
                query section of the URL.
        """
        return self._request_without_payload("DELETE", path, params=params)
