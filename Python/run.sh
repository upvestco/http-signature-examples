#!/usr/bin/env bash

# Make Bash's error handling strict(er).
set -o nounset -o pipefail -o errexit

python3 -m venv ./venv
source ./venv/bin/activate
pip install -r requirements.txt

# # This can be used to test the "upvest_investment_api" package before publishing it.
# # TODO implement "proper" local installation together with installing "extras".
# pip install pkg/upvest_investment_api/dist/upvest_investment_api-0.0.1a3-py3-none-any.whl 'requests>=2.31.0' 'PGPy>=0.6.0' 'environs>=9.5.0'

python main.py
