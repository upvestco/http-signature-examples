# Overview

This directory contains the basic outline of a working Upvest
Investment API client in Python3.

The intent of this code is to show you how to implement V15 of the
HTTP Message Signing mechanism and authorisation token acquisation
you'll need to securely access the Upvest Investment API.

# Installing the example

**Prerequisites**
- It is assumed that you have Python3 installed on your machine,
  following whatever procedure is suggested/validated in your company.

The easiest way to prepare your machine to the run the example is to
use a Python3 virtual environment. The following steps will clone this
repository and set up such an environment:

```sh
git clone git@github.com/toknapp/http-signature-examples.git 
cd http-signature-examples/Python
python3 -m venv ./venv
source ./venv/bin/activate
```

You should now be in a Python3 virtual environment, as indicated by
your shell prompt, which should now look something like this:

```sh
(venv) your-name@your-computer Python % 
```

Should you wish to exit the virtual environment, you can simply issue
the `deactivate` command.


You can now install the projects dependencies into your virtual
environment (remembering to reactivate it first if you just issued the
`deactivate` command).

```sh
pip3 install -r requirements.txt
```

This single command will ensure that all project dependencies are in place.

# Running the example
You should be able to run the `sign.py` script in this directory by
invoking the following (replacing the values with your real PEM file,
PEM Password, pre-shared Key ID, Client ID and Client Secret):

```sh
python3 sign.py "./my_ecdsa521.pem" "my-secret-pem-password" "pre-shared-key-id" \
	"my-client-id" "my-client-secret"
```

# Understanding the example

Please make sure you have read and understood the associated
[documentation on implementing message
signing.](https://docs.upvest.co/tutorials/implementing_http_signatures)

Though the top-level `sign.py` script is informative in terms of how
payloads can be structured, the core of the logic in this example
lives within the `UpvestAPI` class, which you can find in the `upvest`
sub-directory, in the `http.py` file.

The initialisation of the `UpvestAPI` class causes the provide PEM
file to be loaded, the content decrypted using the PEM password, and
the contained private key to be loaded into memory.  Thereafter the
instance is ready for use.

The public methods of the `UpvestAPI` class map to HTTP request types:
`get`, `post`, `patch`, `put` and `delete`. You will notice that each
of these requests types resolves to one of two underlying, private
methods: `_request_without_payload` and `_request_with_payload`.

Both of these methods follow the process:
- acquire an authorisation token
- define required headers
- calculate the message signature and insert it into the message headers

You will notice that the required headers and the input to the message
signature vary based on the type of request being made.  In
particular, request types that carry a payload in the body of the
message (`post`, `put`, `patch`) will require a `Content-Digest`
header to be calculated and included in the headers and signature
payload.  Request types that don't have a payload in the body (`get`
and `delete`) must omit the `Content-Digest`.

It is important to respect theses distinctions in your own requests.
Generating a signature with the wrong types or wrong format of input
is the most common kind of error you'll see in creating the message
signatures, and often the hardest to debug.
