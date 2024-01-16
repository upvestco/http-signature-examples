# Upvest Investment API

This Python package is **NOT** a fully fledged API client.

So far, it implements the parts of the [HTTP Message Signatures, draft version 15](https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-message-signatures-15) functionality which are required to interact with the [Upvest Investment API](https://docs.upvest.co/).

Next to a generic implementation, this is also provided as a [custom authentication mechanism](https://requests.readthedocs.io/en/latest/user/advanced/#custom-authentication) for [the `requests` Python package](https://requests.readthedocs.io/en/latest/) when you install this package with the `requests-auth` extra enabled like so: `pip install upvest-investment-api[requests-auth]`

For examples how to use this, please refer to Upvest's [Python code examples](https://github.com/upvestco/http-signature-examples/tree/main/Python).


## Required dependency

This Python package relies on [the `cryptography` package](https://pypi.org/project/cryptography/) to do the heavy lifting for HTTP Message Signatures.


## Optional dependencies / Package extras

This Python package uses [optional dependencies](https://setuptools.pypa.io/en/latest/userguide/dependency_management.html#optional-dependencies) to give you control over which additional dependencies get installed when using it:

- The package extra `requests-auth` installs [the `requests` package](https://pypi.org/project/requests/) which is required to provide the `requests` custom authentication mechanism mentioned above.
- The package extra `file-download` installs [the `requests` package](https://pypi.org/project/requests/) and [the `PGPy` package](https://pypi.org/project/PGPy/) which both are required to enable downloading files from the Upvest Investment API. See how to use it in this [MiFIR report file download code example](https://github.com/upvestco/http-signature-examples/blob/main/Python/download_mifir_report.py).
- The package extra `env-settings` installs [the `environs` package](https://pypi.org/project/environs/) which is used to load all settings and the access credentials for the Upvest Investment API from environment variables.

You can specify multiple extras at the same time as a comma-separated list like so: `pip install upvest-investment-api[requests-auth,env-settings,file-download]`, optionally pinning the version like so: `pip install upvest-investment-api[requests-auth,env-settings,file-download]==0.0.1a3`
