#!/bin/sh
set -eu
# Run from a directory containing tests/, but not the plugin source package.
python -m pip check
python -c 'import django, wagtail; print("Django", django.get_version(), "Wagtail", wagtail.__version__)'
python -m django check
python -m django makemigrations --check --dry-run
python -m django test tests --verbosity 2
python -m django collectstatic --noinput --verbosity 0
python -c 'from importlib.resources import files; import wagtail_soca; assert wagtail_soca.__version__ == "0.0.1"; assert files("wagtail_soca").joinpath("templates/wagtailadmin/login.html").is_file(); assert files("wagtail_soca").joinpath("migrations/0003_claiminspection.py").is_file(); print("Installed wheel verified")'
