#!/usr/bin/env bash
set -euo pipefail

# Install dependencies via Pipfile
pipenv install

SITE_PACKAGES="$(pipenv run python -c 'import sysconfig; print(sysconfig.get_paths()["purelib"])')"

# Create zip with Lambda handler and NFCU module
zip -9 nfcu_alexa_skill.zip lambda_function.py
zip -ur -9 nfcu_alexa_skill.zip nfcu/ -i "*.py"
zip -ur -9 nfcu_alexa_skill.zip nfcu/ -i "*.json"

# Bundle dependencies
(cd "$SITE_PACKAGES" && zip -ur -9 "$OLDPWD/nfcu_alexa_skill.zip" . -i "*.py" "*.pem")
