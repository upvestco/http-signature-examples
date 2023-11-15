import base64
from environs import Env, EnvError


env = Env()

# TODO find a way to use `.env.example` as default values.
# Calling `env.read_env()` twice doesn't work.
env.read_env('.env', recurse=False)


def load_private_key(env: Env, key_name: str) -> bytes:
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

    raise EnvError(f'Either {key_name}_FILENAME, {key_name} or {key_name}_BASE64 env var needs to be set.')


UPVEST_API_HTTP_SIGN_PRIVATE_KEY = load_private_key(env, 'UPVEST_API_HTTP_SIGN_PRIVATE_KEY')
UPVEST_API_HTTP_SIGN_PRIVATE_KEY_PASSPHRASE = env.str('UPVEST_API_HTTP_SIGN_PRIVATE_KEY_PASSPHRASE')
UPVEST_API_HTTP_SIGN_PRIVATE_KEY_PASSPHRASE_BYTES = bytes(UPVEST_API_HTTP_SIGN_PRIVATE_KEY_PASSPHRASE, 'utf-8')

UPVEST_API_BASE_URL = env.str('UPVEST_API_BASE_URL')
UPVEST_API_KEY_ID = env.str('UPVEST_API_KEY_ID')
UPVEST_API_CLIENT_ID = env.str('UPVEST_API_CLIENT_ID')
UPVEST_API_CLIENT_SECRET = env.str('UPVEST_API_CLIENT_SECRET')
UPVEST_API_SCOPES = env.list('UPVEST_API_SCOPES')

# OPTIONAL
# These are only used for downloading files from the Files API
# @see .env.example
# @see download_mifir_report.py
try:
    UPVEST_API_FILE_ENCRYPTION_PRIVATE_KEY = load_private_key(env, 'UPVEST_API_FILE_ENCRYPTION_PRIVATE_KEY')
except EnvError:
    # Well, it's optional, after all.
    UPVEST_API_FILE_ENCRYPTION_PRIVATE_KEY = b''
UPVEST_API_FILE_ENCRYPTION_PRIVATE_KEY_PASSPHRASE = env.str('UPVEST_API_FILE_ENCRYPTION_PRIVATE_KEY_PASSPHRASE', '')
UPVEST_API_FILE_ENCRYPTION_PRIVATE_KEY_PASSPHRASE_BYTES = bytes(UPVEST_API_FILE_ENCRYPTION_PRIVATE_KEY_PASSPHRASE, 'utf-8')
UPVEST_API_FILE_NAMESPACE = env.str('UPVEST_API_FILE_NAMESPACE', 'mifir_reports')
# NOTE: The following value, including it's default, is a string which gets
# formatted elsewhere. It must carry a `{filename_timestamp}` replacement
# field, but must not be formatted here, in order to work properly.
UPVEST_API_FILENAME_TEMPLATE = env.str('UPVEST_API_FILENAME_TEMPLATE', 'mifir_reporting_files_{filename_timestamp}.zip')
EXAMPLE_REPORT_DATE = env.date('EXAMPLE_REPORT_DATE', default=None)
