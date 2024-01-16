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
import warnings

# 3rd-party imports
import pgpy
import requests

# local imports
from .requests_auth import UpvestRequestsAuth


class DownloadError(Exception):
    """Indicates that something went wrong when downloading a file.

    Should have more info inside the `message` field.
    """
    pass


def download_file_content(base_url: str, file_namespace: str, filename: str, upvest_auth: UpvestRequestsAuth) -> bytes:
    """Downloads a file from the Upvest Investment API."""
    download_url = f'{base_url}/files/{file_namespace}/{filename}'
    params = {'redirect': 1}
    res = requests.get(download_url, params=params, auth=upvest_auth)
    if res.status_code == 200:
        return res.content
    else:
        raise DownloadError(f'unable to download {download_url}, got {res.status_code} with Upvest request ID: {res.headers["upvest-request-id"]}')


def decrypt_pgp(pgp_private_key_blob: bytes, pgp_private_key_passphrase: str, encrypted_message: bytes) -> str:
    """Decrypts a PGP message."""

    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        # The `cryptography` package warns about IDEA, CAST5 and Blowfish being
        # deprecated, but `pgpy` needs to still use them to conform with the
        # OpenPGP standard.
        # That's why I'm suppressing warnings here.
        # TODO only suppress `CryptographyDeprecationWarning`

        key, _ = pgpy.PGPKey.from_blob(pgp_private_key_blob)
        encrypted_message_parsed = pgpy.PGPMessage.from_blob(encrypted_message)

        with key.unlock(pgp_private_key_passphrase) as unlocked_key:
            decrypted_message = unlocked_key.decrypt(encrypted_message_parsed)

        return decrypted_message.message
