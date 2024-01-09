# Python Standard Library imports
import datetime
import gzip
import io
import sys
import warnings
import zipfile

# 3rd-party imports
import pgpy
import requests

# local imports
import settings
from upvest_investment_api import has_requests_auth
if has_requests_auth:
    from upvest_investment_api import UpvestRequestsAuth
else:
    sys.exit("You need to install the upvest-investment-api Python package with the requests-auth extra, like so: `pip install upvest-investment-api[requests-auth]`")


def setup_upvest_auth() -> UpvestRequestsAuth:
    """Uses settings from env vars to initialise an `auth` middleware for the `requests` library."""
    return UpvestRequestsAuth(
        private_key_pem=settings.UPVEST_API_HTTP_SIGN_PRIVATE_KEY,
        private_key_password_bytes=settings.UPVEST_API_HTTP_SIGN_PRIVATE_KEY_PASSPHRASE_BYTES,
        key_id=settings.UPVEST_API_KEY_ID,
        client_id=settings.UPVEST_API_CLIENT_ID,
        client_secret=settings.UPVEST_API_CLIENT_SECRET,
        scopes=settings.UPVEST_API_SCOPES,
    )


# A list of days to skip when trying to get from "today" to the day for which to download a report.
NON_TRADING_DAYS = [datetime.date.fromisoformat(isodate) for isodate in [
    # These are not complete!!!
    '2023-12-25',
    '2023-12-26',
]]


# For those seemingly "random" values,
# @see https://docs.python.org/3/library/datetime.html#datetime.date.weekday
# These will become part of the language in Python 3.12:
# @see https://docs.python.org/3.12/library/calendar.html#calendar.Day
SATURDAY = 5
SUNDAY = 6
WEEKEND = (SATURDAY, SUNDAY)
ONE_DAY = datetime.timedelta(days=1)


def guess_previous_report_coverage_date(today: datetime.date):
    """Guess the date for the latest report available today.

    This is a **very naive** implementation of "T+1" business logic.
    You might already have a better version yourself.
    """
    day_cursor = today - ONE_DAY  # Go back one day at least.
    while day_cursor.weekday() in WEEKEND or day_cursor in NON_TRADING_DAYS:
            day_cursor -= ONE_DAY
    return day_cursor


class DownloadError(Exception):
    """Indicates that something went wrong when downloading a file.

    Should have more info inside the `message` field.
    """
    pass


def download_mifir_report_file_content(report_coverage_date: datetime.date, upvest_auth: UpvestRequestsAuth) -> bytes:
    """Downloads a MiFir report file from the Upvest Investment API."""
    filename_timestamp = report_coverage_date.strftime('%Y%m%d')
    filename = settings.UPVEST_API_FILENAME_TEMPLATE.format(filename_timestamp=filename_timestamp)
    download_url = f'{settings.UPVEST_API_BASE_URL}/files/{settings.UPVEST_API_FILE_NAMESPACE}/{filename}'
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


def decrypt_report_file(report_file_content: bytes) -> bytes:
    """Decrypts the report file with PGP, if a file encryption key is configured.

    See `.env.example` for how to configure this.
    """
    if b'' == settings.UPVEST_API_FILE_ENCRYPTION_PRIVATE_KEY:
        # No key means no encryption.
        return report_file_content

    return decrypt_pgp(
        settings.UPVEST_API_FILE_ENCRYPTION_PRIVATE_KEY,
        settings.UPVEST_API_FILE_ENCRYPTION_PRIVATE_KEY_PASSPHRASE,
        report_file_content
    )


def get_most_recent_mifir_report() -> dict[str, bytes]:
    """Provides the report file contents which you have to upload to BaFin today.

    Combines all steps to end up with the contents of the report files which you are meant to upload to BaFin.
    """
    upvest_auth = setup_upvest_auth()
    today = datetime.date.today()
    report_coverage_date = guess_previous_report_coverage_date(today)

    # In some environments, report files are only available for some fixed dates.
    if settings.EXAMPLE_REPORT_DATE is not None:
        report_coverage_date = settings.EXAMPLE_REPORT_DATE

    report_file_content_downloaded = download_mifir_report_file_content(report_coverage_date, upvest_auth)
    report_file_content_decrypted = decrypt_report_file(report_file_content_downloaded)
    with zipfile.ZipFile(io.BytesIO(report_file_content_decrypted), mode='r') as zip:
        return {filename: zip.read(filename) for filename in zip.namelist()}


def main():
    files = get_most_recent_mifir_report()
    # At this point, you have a dict `files` with filenames mapped to binary file contents.
    # Since I'm agnostic of your environment, I did not try to access any file system.
    #
    # There was most likely only one file inside the *.zip container.
    # I'm not enough of a subject matter expert to know that this will hold true at all times,
    # that's why I decided to use a dict instead of a single (name, content) tuple.
    #
    # I *believe* you don't need to uncompress the *.gz files here,
    # since you will upload them as-is to BaFin. (?)

    # TODO Remove the following debugging & demonstration output.
    # TODO Implement any further report files processing.

    # But for debugging & demonstration purposes in this example, none-the-less, inspect all gzipped files:
    for filename, gzipped in files.items():
        with gzip.GzipFile(fileobj=io.BytesIO(gzipped), mode='rb') as ungzipped:
            file_content = ungzipped.read()
            print('UNCOMRESSED FILE NAME:', filename)
            print('-----------BEGIN UNCOMRESSED FILE-----------')
            print(file_content.decode())
            print('-----------END   UNCOMRESSED FILE-----------')


if __name__ == '__main__':
    main()
