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


#!/usr/bin/env bash

# Make Bash's error handling strict(er).
set -o nounset -o pipefail -o errexit

python3 -m venv ./venv
source ./venv/bin/activate

python3 -m pip install -r requirements.txt
# Always use latest build pipeline.
python3 -m pip install --upgrade pip build twine

echo "When asked, please enter '__token__' as the username, and a PyPI API token as the password."
echo "For how to get such a token, see https://packaging.python.org/en/latest/tutorials/packaging-projects/#uploading-the-distribution-archives"
echo "HINT: You can install such a token in a ~/.pypirc file, then you won't get asked."

# TODO Automate publishing.

for d in $(find . -name "pyproject.toml" -exec dirname {} \;)
do
    pushd . # "pkg" dir
    cd "$d"
    rm -rf dist/*
    python3 -m build
    python3 -m twine upload dist/*
    popd # "pkg" dir
done
