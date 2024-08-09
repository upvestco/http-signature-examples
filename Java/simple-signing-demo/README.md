# Overview

This directory contains a basic example of a making a request to the Upvest Investment API in Java.

The intent of this code is to show you how to implement [version 15 of the
HTTP Message Signature standard draft](https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-message-signatures-15)
and authorisation token acquisition, which you'll need to securely access
the Upvest Investment API.


## Examining the example

**Prerequisites**

This example makes the following assumptions:

- You have Java 21 or later installed on your machine.
- You have generated an ECDSA private / public key pair according to
  [our signature tutorial](https://docs.upvest.co/tutorials/implementing_http_signatures_v15#ecdsa).
  (The Python code examples do not support Ed25519 signatures yet.)
- You have shared the public key with Upvest and have
  received a set of API credentials from Upvest.

**Installation steps**

Clone this repository:

```sh
git clone git@github.com:upvestco/http-signature-examples.git
```

Change directory to the Java/simple-signing-demo sub-directory and create
a `env.properties` configuration file from the provided `env.properties.tmpl` template:

```sh
cd http-signature-examples/Java/simple-signing-demo
cp env.properties.tmpl env.properties
```


Open the `env.properties` file with a text editor and fill in the values pertaining
to the private key and to the API credentials as described in the comments.

```
UPVEST_API_HTTP_SIGN_PRIVATE_KEY_FILE= # Path to the private key file
UPVEST_API_HTTP_SIGN_PRIVATE_KEY_PASSPHRASE= # Passphrase for the private key
UPVEST_API_KEY_ID= # API key ID
UPVEST_API_CLIENT_ID= # API client ID
UPVEST_API_CLIENT_SECRET= # API client secret
UPVEST_URL= # URL of the Upvest API
```

## Running the example

The example uses the [Gradle](https://gradle.com) build system. You can run the example with the following command:

```sh
./gradlew test
```

The output on the console should end with
```
BUILD SUCCESSFUL in x ms
```

The test queries a list of users. You can find the result of the test in `http-signature-examples/Java/simple-signing-demo/build/test-results/test/TEST-co.upvest.client.GetUsersTest.xml`.


## Understanding the example

Please browse the source code. Feel free to ask questions, or to create issues for improvement suggestions (or PRs with improvements).

