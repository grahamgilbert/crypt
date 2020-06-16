#!/bin/zsh
# Build script for Python 3 framework for Sal scripts
TOOLSDIR=$(dirname "$0")
PYTHON_VERSION=3.8.2

# build the framework
/tmp/relocatable-python/make_relocatable_python_framework.py \
    --python-version "${PYTHON_VERSION}" \
    --pip-requirements requirements.txt \
    --destination "${TOOLSDIR}"
