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
import datetime
import gzip
import io
import sys
import warnings
import zipfile

# 3rd-party imports
import pgpy
import requests

# "example-as-a-usable-package" import
from upvest_investment_api import has_requests_auth, has_file_download, has_env_settings

if has_requests_auth:
    from upvest_investment_api import UpvestRequestsAuth
else:
    sys.exit("You need to install the upvest-investment-api Python package with the requests-auth extra, like so: `pip install upvest-investment-api[requests-auth]`")

if has_file_download:
    from upvest_investment_api import download_file_content, decrypt_pgp
else:
    sys.exit("You need to install the upvest-investment-api Python package with the file-download extra, like so: `pip install upvest-investment-api[file-download]`")

if has_env_settings:
    from upvest_investment_api import FileDownloadSettings, HttpSignatureSettings
else:
    sys.exit("You need to install the upvest-investment-api Python package with the env-settings extra, like so: `pip install upvest-investment-api[env-settings]`")


def setup_upvest_auth(settings: HttpSignatureSettings) -> UpvestRequestsAuth:
    """Uses settings from env vars to initialise an `auth` middleware for the `requests` library."""
    return UpvestRequestsAuth(
        private_key_pem=settings.HTTP_SIGN_PRIVATE_KEY,
        private_key_passphrase=settings.HTTP_SIGN_PRIVATE_KEY_PASSPHRASE,
        key_id=settings.KEY_ID,
        client_id=settings.CLIENT_ID,
        client_secret=settings.CLIENT_SECRET,
        scopes=settings.SCOPES,
    )


# A list of days to skip when trying to get from "today" to the day for which to download a report.
# See for example https://www.tradegate.de/handelskalender.php?lang=en
NO_TRADING_AND_NO_SETTLEMENT_DAYS = [datetime.date.fromisoformat(isodate) for isodate in [
    # These are not complete!!!
    '2024-01-01',  # New Year's Day: no trading
    '2024-03-29',  # Good Friday: no trading
    '2024-04-01',  # Easter Monday: no trading
    '2024-05-01',  # (German) Labour Day: no trading
    '2024-12-25',  # Christmas Day: no trading
    '2024-12-26',  # Boxing Day: no trading
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
    while day_cursor.weekday() in WEEKEND or day_cursor in NO_TRADING_AND_NO_SETTLEMENT_DAYS:
        day_cursor -= ONE_DAY
    return day_cursor


def download_mifir_report_file_content(report_coverage_date: datetime.date, upvest_auth: UpvestRequestsAuth, settings: HttpSignatureSettings, dl_settings: FileDownloadSettings) -> bytes:
    """Downloads a MiFir report file from the Upvest Investment API."""
    filename_timestamp = report_coverage_date.strftime('%Y%m%d')
    filename = dl_settings.FILENAME_TEMPLATE.format(filename_timestamp=filename_timestamp)
    return download_file_content(settings.BASE_URL, dl_settings.FILE_NAMESPACE, filename, upvest_auth)


def decrypt_report_file(report_file_content: bytes, dl_settings: FileDownloadSettings) -> bytes:
    """Decrypts the report file with PGP, if a file encryption key is configured.

    See `.env.example` for how to configure this.
    """
    if b'' == dl_settings.FILE_ENCRYPTION_PRIVATE_KEY:
        # No key means no encryption.
        return report_file_content

    return decrypt_pgp(
        dl_settings.FILE_ENCRYPTION_PRIVATE_KEY,
        dl_settings.FILE_ENCRYPTION_PRIVATE_KEY_PASSPHRASE,
        report_file_content
    )


def get_most_recent_mifir_report(settings: HttpSignatureSettings, dl_settings: FileDownloadSettings) -> dict[str, bytes]:
    """Provides the report file contents which you have to upload to BaFin today.

    Combines all steps to end up with the contents of the report files which you are meant to upload to BaFin.
    """
    upvest_auth = setup_upvest_auth(settings)
    today = datetime.date.today()
    report_coverage_date = guess_previous_report_coverage_date(today)

    # In some environments, report files are only available for some fixed dates.
    if dl_settings.EXAMPLE_REPORT_DATE is not None:
        report_coverage_date = dl_settings.EXAMPLE_REPORT_DATE

    report_file_content_downloaded = download_mifir_report_file_content(report_coverage_date, upvest_auth, settings, dl_settings)
    report_file_content_decrypted = decrypt_report_file(report_file_content_downloaded, dl_settings)
    with zipfile.ZipFile(io.BytesIO(report_file_content_decrypted), mode='r') as zip:
        return {filename: zip.read(filename) for filename in zip.namelist()}


def main():
    settings = HttpSignatureSettings()
    dl_settings = FileDownloadSettings()

    files = get_most_recent_mifir_report(settings, dl_settings)
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
