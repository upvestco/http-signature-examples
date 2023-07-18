import datetime

import upvest.auth as up_auth
import requests


class AuthorisationFailedError(Exception):
    "Raised when a request for an Authorisation token fails."

    def __init__(self, response, message="Request for an Authorisaton token failed"):
        self.response = response
        self.message = message
        super().__init__(self.message)


class UpvestAPI():

    default_covered_component_ids=['accept', 'content-type',
                                   'upvest-client-id', 'authorization',
                                   '@method', '@path']
    _token_expirey_buffer = 5
    
    def __init__(self, host, pem_file_path, pem_password, preshared_key_id, client_id, client_secret, scopes=[]):
        self._host = host
        self._pk = up_auth.read_private_key_from_pem(pem_file_path)
        self._preshared_key_id = preshared_key_id
        self._client_id = client_id
        self._client_secret = client_secret
        self._scopes=scopes
        self._session = requests.Session()
        self._token = None
        self._token_expires = datetime.datetime.now()
        self._alg = up_auth.create_algorithm(pem_password)
        up_auth.register_algorithm(self._alg)
        
        
    def _auth(self):
        base_time = datetime.datetime.now()
        if self._token_expires > base_time + datetime.timedelta(self._token_expirey_buffer):
            return 


        auth = up_auth.UpvestHTTPSignatureAuth(signature_algorithm=self._alg,
                                               key=self._pk,
                                               key_id=self._preshared_key_id,
                                               covered_component_ids=['accept', 'content-length', 'content-type',
                                                                      'upvest-client-id',
                                                                      '@method', '@path', 'content-digest'],
                                               use_nonce=True,
                                               include_alg=False,
                                               expires_in=datetime.timedelta(seconds=20),
                                               )
        url = self._host + "/auth/token"
        req = requests.Request("POST", url,
                               auth=auth,
                               headers={
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
        resp = self._session.send(prepped)
        if resp.status_code != 200:
            raise AuthorisationFailedError(resp)

        self._token = resp.json()
        self._token_expires = base_time + datetime.timedelta(seconds=int(self._token['expires_in']))

        
    def get(self, path, params=None):
        self._auth()
        covered_component_ids = self.default_covered_component_ids
        if params:
            covered_component_ids.append("@query")
    
        auth = up_auth.UpvestHTTPSignatureAuth(signature_algorithm=self._alg,
                                               key=self._pk,
                                               key_id=self._preshared_key_id,
                                               covered_component_ids=covered_component_ids,
                                               use_nonce=True,
                                               include_alg=False,
                                               expires_in=datetime.timedelta(seconds=20),
                                           )
        url = self._host + path
        req = requests.Request("GET", url,
                               params=params,
                               auth=auth,
                               headers={
                               "Accept": "application/json",
                               "upvest-client-id": self._client_id,
                               "authorization": "Bearer %s" % self._token["access_token"],
                               "Content-Type": "application/json",
                               "Upvest-Signature-Version": "15",
                           })
        prepped = req.prepare()
        return self._session.send(prepped)


        
