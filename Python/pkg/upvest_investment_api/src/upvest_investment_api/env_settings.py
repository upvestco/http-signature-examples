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


import base64
from environs import Env, EnvError


def load_private_key(env: Env, key_name: str, prefix: str = 'UPVEST_API_') -> bytes:
    private_key_pem_filename = env.str(f'{key_name}_FILENAME', default='')
    if private_key_pem_filename != '':
        # This does access the file system, for the benefit of (my own) local development.
        # For file-system-free alternatives, see {key_name} or {key_name}_BASE64.
        with open(private_key_pem_filename, 'rb') as kf:
            return kf.read()
    else:
        private_key_pem = env.str(key_name, default='')
        if private_key_pem != '':
            return bytes(private_key_pem, 'utf-8')
        else:
            private_key_pem_base64 = env.str(f'{key_name}_BASE64', default='')
            if private_key_pem_base64 != '':
                return base64.b64decode(private_key_pem_base64)

    raise EnvError(f'Either {prefix}{key_name}_FILENAME, {prefix}{key_name} or {prefix}{key_name}_BASE64 env var needs to be set.')


class HttpSignatureSettings:
    def __init__(self, env_file: str = '.env', prefix: str = 'UPVEST_API_'):
        env = Env()
        env.read_env(env_file, recurse=False)
        with env.prefixed(prefix):
            self.HTTP_SIGN_PRIVATE_KEY = load_private_key(env, 'HTTP_SIGN_PRIVATE_KEY', prefix)
            self.HTTP_SIGN_PRIVATE_KEY_PASSPHRASE = bytes(env.str('HTTP_SIGN_PRIVATE_KEY_PASSPHRASE'), 'utf-8')
            self.BASE_URL = env.str('BASE_URL', 'https://sandbox.upvest.co')
            self.KEY_ID = env.str('KEY_ID')
            self.CLIENT_ID = env.str('CLIENT_ID')
            self.CLIENT_SECRET = env.str('CLIENT_SECRET')
            self.SCOPES = env.list('SCOPES')


class FileDownloadSettings:
    def __init__(self, env_file: str = '.env', prefix: str = 'UPVEST_API_'):
        env = Env()
        env.read_env(env_file, recurse=False)
        with env.prefixed(prefix):
            try:
                self.FILE_ENCRYPTION_PRIVATE_KEY = load_private_key(env, 'FILE_ENCRYPTION_PRIVATE_KEY', prefix)
                self.HAS_FILE_ENCRYPTION = True
            except EnvError:
                # Well, it's optional, after all.
                self.FILE_ENCRYPTION_PRIVATE_KEY = b''
                self.HAS_FILE_ENCRYPTION = False
            self.FILE_ENCRYPTION_PRIVATE_KEY_PASSPHRASE = bytes(env.str('FILE_ENCRYPTION_PRIVATE_KEY_PASSPHRASE', ''), 'utf-8')
            self.FILE_NAMESPACE = env.str('FILE_NAMESPACE', 'mifir_reports')
            # NOTE: The following value, including it's default, is a string which gets
            # formatted elsewhere. It must carry a `{filename_timestamp}` replacement
            # field, but must not be formatted here, in order to work properly.
            self.FILENAME_TEMPLATE = env.str('FILENAME_TEMPLATE', 'mifir_reporting_files_{filename_timestamp}.zip')
            self.EXAMPLE_REPORT_DATE = env.date('EXAMPLE_REPORT_DATE', default=None)
