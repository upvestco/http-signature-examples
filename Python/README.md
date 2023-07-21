This directory contains the basic outline of a working Upvest
Investment API client in Python3.

The intent of this code is to show you how to implement V15 of the
HTTP Message Signing mechanism and authorisation token acquisation
you'll need to securely access the Upvest Investment API.

You should be able to run the `sign.py` script in this directory by
invoking the following (replacing the values with your real PEM file,
PEM Password, pre-shared Key ID, Client ID and Client Secret):

```sh
python3 sign.py "./my_ecdsa521.pem" "my-secret-pem-password" "pre-shared-key-id" \
	"my-client-id" "my-client-secret"
```

Please make sure you have read and understood the associated [documentation on implementing message signing.](https://docs.upvest.co/tutorials/implementing_http_signatures) 
