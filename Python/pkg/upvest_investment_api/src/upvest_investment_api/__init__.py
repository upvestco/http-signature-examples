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


from .http_message_signatures import (
    CanonicalisationError,
    CREATED_NOW_SENTINEL_VALUE,
    HttpMessageSigner,
    UPVEST_ACCEPTABLE_ACCEPT_HEADER_VALUES,
    UPVEST_IGNORABLE_HEADER_PREFIXES,
    UpvestHttpMessageSigner,
    make_idempotency_key,
)

try:
    from .requests_auth import (
        AuthorisationError,
        UpvestRequestsAuth,
    )
    # TODO Maybe check that the required version of `requests` has been met?
    # See https://discuss.python.org/t/how-to-detect-which-extras-were-installed-at-runtime/15367/9
    # See https://github.com/pypa/packaging-problems/issues/215
    export_requests_auth = (
        "AuthorisationError",
        "UpvestRequestsAuth",
    )
    has_requests_auth = True
except ImportError:
    export_requests_auth = tuple()
    has_requests_auth = False


try:
    from .file_download import (
        DownloadError,
        download_file_content,
        decrypt_pgp,
    )
    # TODO Maybe check that the required versions of `requests` and `PGPy` has been met?
    # See https://discuss.python.org/t/how-to-detect-which-extras-were-installed-at-runtime/15367/9
    # See https://github.com/pypa/packaging-problems/issues/215
    export_file_download = (
        "DownloadError",
        "download_file_content",
        "decrypt_pgp",
    )
    has_file_download = True
except ImportError:
    export_file_download = tuple()
    has_file_download = False


try:
    from .env_settings import (
        HttpSignatureSettings,
        FileDownloadSettings,
    )
    # TODO Maybe check that the required version of `environs` has been met?
    # See https://discuss.python.org/t/how-to-detect-which-extras-were-installed-at-runtime/15367/9
    # See https://github.com/pypa/packaging-problems/issues/215
    export_env_settings = (
        "HttpSignatureSettings",
        "FileDownloadSettings",
    )
    has_env_settings = True
except ImportError:
    export_env_settings = tuple()
    has_env_settings = False


__all__ = (
    "CanonicalisationError",
    "CREATED_NOW_SENTINEL_VALUE",
    "HttpMessageSigner",
    "UPVEST_ACCEPTABLE_ACCEPT_HEADER_VALUES",
    "UPVEST_IGNORABLE_HEADER_PREFIXES",
    "UpvestHttpMessageSigner",
    "make_idempotency_key",
    "has_requests_auth",
    "has_file_download",
    "has_env_settings",
) + export_requests_auth + export_file_download + export_env_settings
