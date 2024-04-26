# Overview

This directory contains the basic outline of a working Upvest
Investment API client in Python3.

The intent of this code is to show you how to implement [version 15 of the
HTTP Message Signature standard draft](https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-message-signatures-15)
and authorisation token acquisition, which you'll need to securely access
the Upvest Investment API.

Please note that the reusable parts of this example's functionality are
available as [the `upvest-investment-api` Python package](https://pypi.org/project/upvest-investment-api/).
The source code for that package is hosted [here](https://github.com/upvestco/http-signature-examples/tree/main/Python/pkg/upvest_investment_api)
in this Github repository.


## Installing the example

**Prerequisites**

This example makes the following assumptions:

- You have either Python (version >= 3.10) or Docker
  installed on your machine, following whatever procedure is
  suggested/validated in your company.
- You have generated an ECDSA private / public key pair according to
  [our signature tutorial](https://docs.upvest.co/tutorials/implementing_http_signatures_v15#ecdsa).
  (The Python code examples do not support Ed25519 signatures yet.)
- You have shared the public key with Upvest and have
  received a set of API credentials from Upvest.

**Installion steps**

Clone this repository:

```sh
git clone git@github.com:upvestco/http-signature-examples.git
```

Change directory to the Python sub-directory and create
a `.env` configuration file from the provided `.env.example` template:

```sh
cd http-signature-examples/Python
cp .env.example .env
```

Open the `.env` file with a text editor and fill in the values pertaining
to the private key and to the API credentials as described in the comments in
`.env`.


## Running the example

You can either run this example with Python installed directly on your
machine, or inside a Docker container.

### Running directly on Python

Just run this:

```sh
./run.sh
```

(This should also take care of installing the dependencies which match your
local Python version.)

The output is supposed to be a sequence of request / response pairs.

### Running inside a Docker container

Start up the docker container like so:

```sh
make run
```

This should drop you into a bash shell inside the container.

There, you just run this:

```sh
./run.sh
```

The output is supposed to be a sequence of request / response pairs.


## Running the file download example directly on Python

Please coordinate with Upvest staff for which date a MiFIR report file with
actual transaction data is available.

Set the `UPVEST_API_EXAMPLE_REPORT_DATE` environment variable to that date, in
`YYYY-MM-DD` format.

Again, You can either run this example with Python installed directly on your
machine, or inside a Docker container.

### Running directly on Python

Just run this:

```sh
./run_download.sh
```

(This should also take care of installing the dependencies which match your
local Python version.)

The output is supposed to be the XML of the report file.

### Running inside a Docker container

Start up the docker container like so:

```sh
make run
```

This should drop you into a bash shell inside the container.

There, you just run this:

```sh
./run_download.sh
```

The output is supposed to be the XML of the report file.


## Understanding the example

Please make sure you have read and understood the associated
[documentation on implementing message
signing](https://docs.upvest.co/tutorials/implementing_http_signatures_v15).

Though the top-level [`main.py`](./main.py) and [`download_mifir_report.py`](./download_mifir_report.py)
scripts are informative in terms of how requests and their payloads can be
structured, the majority of the logic in this example is distributed across
the following classes, functions and variables of [the `upvest-investment-api` Python package](https://pypi.org/project/upvest-investment-api/):

- `HttpMessageSigner` holds the "business logic" of creating an HTTP message signature. Does not implements any Upvest-specific additions and stays independent of any HTTP request framework.
  - `CanonicalisationError` is an Exception which gets raised if the provided HTTP request data is not in a form suitable for the signature.
- `UpvestHttpMessageSigner` also creates an HTTP message signature, but adds all Upvest-specifc additional headers. It also stays independent of any HTTP request framework.
- `UpvestRequestsAuth` provides a [custom authentication mechanism](https://requests.readthedocs.io/en/latest/user/advanced/#custom-authentication) for [the `requests` Python package](https://requests.readthedocs.io/en/latest/) which implements the following:
  - HTTP message signatures
  - Upvest-specifc additional headers.
  - Automatically fetches an OAuth token if none is in local memory yet.
    - `AuthorisationError` is an Exception which gets raised if fetching the OAuth token fails.
  - If so instructed for a specific API call, includes an `idempotency-key` header. [The Upvest Investment API requires such a header for some API endpoints](https://docs.upvest.co/concepts/api_concepts/idempotency).
    - `make_idempotency_key` helps generating a string which is suitable as the value for an `idempotency-key` header.
- `download_file_content` implements the steps needed to download a report file from the Upvest Investment API.
- `DownloadError` is an Exception which gets raised if downloading a report file fails.
- `decrypt_pgp` encapsulates the calls to the underlying PGPy library which are needed to decrypt downloaded report files.

These additional helpers might be worth considering as well:

- `has_requests_auth`, `has_file_download`, `has_env_settings` are boolean flag variables which indicate if the respective `requests-auth`, `file-download` or `env-settings` package extras have been installed or not.
- `HttpSignatureSettings` is a suggestion how to load the API credentials and signature key data from environment variables.
- `FileDownloadSettings` is a suggestion how to load the file encryption key data and the report-type-specific download URL parts from environment variables.

You will notice that the required headers and the input to the message
signature vary based on the type of request being made. In
particular, request types that carry a payload in the body of the
message (`POST`, `PUT`, `PATCH`) will require a `content-digest`
header to be calculated and included in the headers and signature
payload. Request types that don't have a payload in the body (`GET`
and `DELETE`) must omit the `content-digest`.

It is important to respect these distinctions in your own requests.
Generating a signature with the wrong types or wrong format of input
is the most common kind of error you'll see in creating the message
signatures, and often the hardest to debug.
