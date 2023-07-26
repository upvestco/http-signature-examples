# Javascript example for HTTP message signing with the Upvest Investment API

## Overview

This directory contains the basic outline of a working
Upvest Investment API client in Javascript.

The intent of this code is to show you how to implement [version 15 of the
HTTP Message Signature standard draft](https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-message-signatures-15)
and authorisation token acquisition, which you'll need to securely access
the Upvest Investment API.


## Installing the example

**Prerequisites**

This example makes the following assumptions:

- You have either Node.js (version >= 18.17.0) or Docker
  installed on your machine, following whatever procedure is 
  suggested/validated in your company.
- You have generated a private / public key pair according to 
  [our signature tutorial](https://docs.upvest.co/tutorials/implementing_http_signatures_v15#ecdsa)
- You have shared the public key with Upvest and have
  received a set of API credentials from Upvest.

**Installion steps**

Clone this repository:

```sh
git clone git@github.com:upvestco/http-signature-examples.git
```

Change directory to the Javascript sub-directory and create
a `.env` configuration file from the provided `.env.example` template:

```sh
cd http-signature-examples/Javascript
cp .env.example .env
```

Open the `.env` file with a text editor and fill in the values pertaining
to the private key and to the API credentials.


## Running the example

You can either run this example with a Node.js installed directly on your
machine, or inside a Docker container.

### Running directly on Node.js

Just run this:

```sh
./run.sh
```

(This should also take care of installing the dependencies which match your local Node.js version.)

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


## Understanding the example

Please make sure you have read and understood the associated
[documentation on implementing message
signing](https://docs.upvest.co/tutorials/implementing_http_signatures_v15).

Though the top-level [`example.mjs`](./example.mjs) script is informative in terms of how
requests and their payloads can be structured, the majority of the logic
in this example is distributed across the following classes and one function:

- [`Signature`](./Signature.mjs') holds the "business logic" of creating an HTTP message signature.
- [`Canonicaliser`](./Canonicaliser.mjs') makes sure that the binary representation of the HTTP message to be signed is identical to what the signature verifier sees on the server side. This is required for successful verification.
- [`NodeCanonicaliser`](./UpvestNodeSigner.mjs') is a subclass of `Canonicaliser`. The prefix `Node*` denotes that extends it's parent class with things that are specific to the Node.js environment.
- [`NodeCryptoProvider`](./UpvestNodeSigner.mjs'): A `CryptoProvider` is an adapter for cryptographic libraries. Here, the prefix `Node*` denotes that this adapter makes the services of the [`node:crypto`](https://nodejs.org/docs/latest-v20.x/api/crypto.html) library available.
- [`NodeKeyLoader`](./NodeKeyLoader.mjs') loads `*.pem` key files and decrypts them with the given password. The prefix `Node*` denotes that this code is specific to the Node.js environment.
- [`upvestNodeSign()`](./UpvestNodeSigner.mjs') is a function which signs HTTP requests. It does so with a generic interface, not specific to any HTTP client library. The prefixes `upvest*` and `Node*` denote that this code is specific to the Upvest Investment API **and** the Node.js environment.
- [`UpvestNodeAxiosInterceptor`](./UpvestNodeAxiosInterceptor.mjs') allows the HTTP message signature code to be installed as a middleware for [the popular `axios` NPM package](https://www.npmjs.com/package/axios). Axios calls it's middleware "interceptor". The prefixes `Upvest*` and `Node*` denote that this code is specific to the Upvest Investment API **and** the Node.js environment.

You will notice that the required headers and the input to the message
signature vary based on the type of request being made. In
particular, request types that carry a payload in the body of the
message (`post`, `put`, `patch`) will require a `content-digest`
header to be calculated and included in the headers and signature
payload. Request types that don't have a payload in the body (`get`
and `delete`) must omit the `content-digest`.

It is important to respect these distinctions in your own requests.
Generating a signature with the wrong types or wrong format of input
is the most common kind of error you'll see in creating the message
signatures, and often the hardest to debug.
