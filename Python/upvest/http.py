# Standard library imports
from email.utils import formatdate
import base64
import datetime
import hashlib
import secrets
import urllib

# 3rd party libraries
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ec import ECDSA
from cryptography.hazmat.primitives.serialization import load_pem_private_key
import requests


class AuthorisationFailedError(Exception):
    "Raised when a request for an Authorisation token fails."

    def __init__(self, response, message="Request for an Authorisaton token failed"):
        self.response = response
        self.message = message
        super().__init__(self.message)


class UpvestAPI():
    """UpvestAPI provides HTTP primitives (GET, POST, PUT, PATCH,
    HEAD, DELETE) enhanced with the HTTP Message Signing required to
    authenticate with Upvest Investment API."""
    
    _token_expiry_buffer = 5
    
    def __init__(self, host, pem_file_path, pem_password, preshared_key_id, client_id, client_secret, scopes=[]):
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

    def _add_digest(self, request):
        if request.body is not None:
            digest = hashlib.sha512(request.body.encode("utf-8")).digest()
            request.headers["Content-Digest"] = "sha-512=:%s:" % \
                base64.b64encode(digest).decode()

    def _sign(self, request, path, created, content_keys=[]):
        sig_key_names = ' '.join(['"' + key + '"' for key in content_keys])
        unix_time = int(created.timestamp())
        nonce = secrets.token_hex(16)
        sig_params = '(%s);keyid="%s";created=%s;expires=%s;nonce="%s"' % \
            (sig_key_names, self._preshared_key_id, unix_time,
             unix_time + 100, nonce)
        sig_input = 'sig1=' + sig_params
        sig_value = ""
        values = {key.lower(): value for key, value in request.headers.items()}
        values["@method"] = request.method
        parts = urllib.parse.urlparse(request.path_url)
        values["@path"] = parts.path
        if parts.query:
            values["@query"] = "?" + parts.query
        for key in content_keys:
            value = values[key]
            sig_value += f'{key}: {value}\n'
        sig_value += f'@signature-params: {sig_params}'

        signature = base64.b64encode(self._pk.sign(sig_value.encode('utf-8'), ECDSA(hashes.SHA512())))
        request.headers["Signature"] = 'sig1=:%s:' % signature.decode()
        request.headers["Signature-Input"] = sig_input
        return request
    
    def _auth(self):
        base_time = datetime.datetime.now()
        if self._token_expires > base_time + datetime.timedelta(
                self._token_expiry_buffer):
            return 

        path = "/auth/token"
        url = self._host + path
        created = datetime.datetime.now()
        
        req = requests.Request("POST", url,
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
        self._add_digest(prepped)
        content_keys = ['accept', 'content-length', 'content-type',
                        'upvest-client-id', '@method', '@path',
                        'content-digest', 'date']
        
        req = self._sign(prepped, path, created, content_keys=content_keys)
        
        resp = self._session.send(prepped)
        if resp.status_code != 200:
            raise AuthorisationFailedError(resp)

        self._token = resp.json()
        self._token_expires = base_time + datetime.timedelta(seconds=int(self._token['expires_in']))

        
    def get(self, path, params=None):
        self._auth()
        content_keys = ['accept', 'content-type',
                        'upvest-client-id', '@method', '@path',
                        'date', 'authorization']

        if params:
            content_keys.append("@query")

        created = datetime.datetime.now()
        url = self._host + path
        req = requests.Request("GET", url,
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


        
