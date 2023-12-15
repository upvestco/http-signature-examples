#!/usr/bin/env bash

# Make Bash's error handling strict(er).
set -o nounset -o pipefail -o errexit

python3 -m venv ./venv
source ./venv/bin/activate
pip install -r requirements.txt
python download_mifir_report.py
