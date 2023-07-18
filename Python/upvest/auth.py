import re
import base64

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec 
from cryptography.hazmat.primitives.serialization import load_pem_private_key
import http_sfv
from requests_http_signature import HTTPSignatureAuth, algorithms

def create_algorithm(pem_password):
    # We require a custom encryption algorithm, both to increase from a
    # SHA-256 to a SHA-512 hash, and also override the handling of the
    # signature pyaload.
    class Upvest_ECDSA_SEC521_SHA512(algorithms.ECDSA_P256_SHA256):
        algorithm_id = "upvest-ECDSA_SEC521_SHA512"
        signing_content_digest_algorithm = "sha-512"

        def __init__(self, public_key=None, private_key=None, password=None):
            self.load_pem_keys(public_key=public_key, private_key=private_key, password=pem_password)
            self.signature_algorithm = ec.ECDSA(hashes.SHA512())

        def sign(self, message: bytes):
            # We have to strip the quotes from the headers in the
            # signature payload - if we don't do this the payload (and
            # thus the signature) won't match Upvest's expectations.
            def repl(m):
                return m[0].replace('"', '')
                
            pattern = r'"(.*)":'
            tmp = re.sub(pattern, repl, message.decode())

            message = tmp.encode()
            ## Uncomment the following lines to dump the raw request to a file for debugging purposes
            # f = open("request.txt", "wb")
            # f.write(message)
            # f.close()
            der_sig = self.private_key.sign(message,
                                            signature_algorithm=self.signature_algorithm)

            return der_sig

    return Upvest_ECDSA_SEC521_SHA512


# We require a custome SignatureAuth subclass to force use of the
# SHA-512 digest and set the header correctly
class UpvestHTTPSignatureAuth(HTTPSignatureAuth):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.signer.DEFAULT_SIGNATURE_LABEL = "sig1"
        self.signing_content_digest_algorithm = "sha-512"


    """add_digest calculatse the digest header from the body of the request."""
    def add_digest(self, request):
        if request.body is None and "content-digest" in self.covered_component_ids:
            raise RequestsHttpSignatureException("Could not compute digest header for request without a body")
        if request.body is not None:
            # Note: this is v15 of the signing algorithm, hence "Content-Digest" rather than "Digest"
            if "Content-Digest" not in request.headers:
                hasher = self._content_digest_hashers["sha-512"]
                digest = hasher(bytes(request.body, "utf-8")).digest()
                encoded_digest = base64.b64encode(digest)
                request.headers["Content-Digest"] = "sha-512=:%s:" % encoded_digest.decode()


"""regisiter_algorithm installs a custom algorithm class for use with HTTPSignatureAuth."""
def register_algorithm(alg):
    algorithms.signature_algorithms[alg.algorithm_id] = alg


def read_private_key_from_pem(pem_file):
    with open(pem_file, 'rb') as fh:
        key = fh.read()
    return key

