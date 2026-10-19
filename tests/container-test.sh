#!/bin/sh
set -eu
ruff check .
ruff format --check .
# Import tests from /suite and the installed plugin from site-packages.
cd /suite
sh tests/run-tests.sh
