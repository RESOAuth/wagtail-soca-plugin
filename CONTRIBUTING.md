# Contributing

Keep changes small, with tests for authentication/admission and permission boundaries. Never include deployment keys, passwords, provider tokens or real-user claim dumps. Report vulnerabilities using [SECURITY.md](SECURITY.md).

## Local checks

Use the [Podman checks](docs/TESTING.md) for reproducible installed-wheel tests. For a virtual environment:

```sh
python -m pip install '.[test]' 'wagtail~=7.4.0' 'Django~=5.2.0'
ruff check .
ruff format --check .
DJANGO_SETTINGS_MODULE=tests.settings python -m django test tests
python -m build
python tests/verify_distribution.py dist
```

Repeat compatibility-sensitive changes with Wagtail 8 and supported Django versions. CI runs tests from outside the source checkout so missing wheel resources cannot be masked by local files. The default tests are synthetic and do not contact a real identity provider. The interactive demo is separate and must not become a CI dependency.

## Pull requests

Describe the behavior, deployment/migration impact and verification. Keep local password recovery, deny-by-default admission, verified-email checks, one-time browser-bound callbacks and existing permissions intact. Add migrations when changing models. Update the changelog and relevant documentation. CI/CodeQL must pass; dependency updates are reviewed rather than automatically merged.

## Releasing

Version 0.0.1 remains an alpha MVP. Review [the release checklist](docs/RELEASING.md) before tagging or publishing. A release PR does not itself publish to PyPI, create a GitHub release or change branch protection.
