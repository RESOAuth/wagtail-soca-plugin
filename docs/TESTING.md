# Testing

Build and run with Podman from the repository root:

```sh
podman build -t wagtail-soca-test:0.0.1 -f Containerfile .
podman run --rm --network=none --read-only \
  --tmpfs /tmp:rw,nosuid,nodev,size=256m wagtail-soca-test:0.0.1
```

The default build downloads the Wagtail 7.4 reference dependencies from `requirements-test.txt`, builds source and wheel distributions, verifies archive contents and metadata, and installs the wheel. Tests run from a separate directory so the installed package is imported. Containers run as UID 10001 with read-only image storage and writable ephemeral `/tmp`; there are no services or persistent volumes to clean up.

Run the same checks on Wagtail 8 without changing a live demo:

```sh
podman build --build-arg WAGTAIL_VERSION=8.0 -t wagtail-soca-test:0.0.1-wagtail8 -f Containerfile .
podman run --rm --network=none --read-only \
  --tmpfs /tmp:rw,nosuid,nodev,size=256m wagtail-soca-test:0.0.1-wagtail8
```

The 8.0 image resolves the additional compatible Wagtail 8 dependencies; it is not an independently pinned environment. CI repeats both container variants and a representative Python/Django matrix: Python 3.10 and 3.14 with Django 5.2 on both Wagtail versions; Python 3.12 with Django 6.0 on both; and Python 3.12/3.14 with Django 6.1 on Wagtail 8.0. Non-container jobs build archives and run `tests/run-tests.sh` against the installed wheel from an isolated suite directory. They resolve compatible dependencies instead of imposing the Python 3.12 reference pins on other runtimes.

CI also runs the full suite on disposable PostgreSQL 17 services for both Wagtail versions, using `tests.settings_postgres` and the optional `postgres-test` extra. No deployment database is used. To reproduce with your own disposable database, install `'.[test,postgres-test]'`, set `PGHOST`, `PGPORT`, `PGUSER`, `PGPASSWORD` and `PGDATABASE`, then run with `DJANGO_SETTINGS_MODULE=tests.settings_postgres`. The test user needs permission to create/drop the isolated test database. Never point these settings at a deployment database.

## Automation and release artifacts

`.github/workflows/ci.yml` runs on every PR, pushes to main and manual dispatch. It checks dependencies, Django configuration, migration drift, templates/static collection and integration tests. The Podman builds additionally run Ruff checks and verify wheel/sdist contents, version/license metadata and absence of private/generated files. Verified distributions are retained as CI artifacts for 14 days; no release or package publication is automatic.

`.github/workflows/codeql.yml` scans Python and GitHub Actions with extended security queries on PRs, main, manual dispatch and weekly. Permissions are read-only except the CodeQL job's result-upload permission; checkout credentials are not persisted. No workflow uses `pull_request_target` or deployment secrets. `.github/dependabot.yml` groups weekly Python, action and container-image update PRs. Scheduled scans and version-update jobs become active after merge to the default branch. Maintainers should review alerts and configure required checks/rulesets separately.

The suite checks Django system configuration, migration drift, lint/formatting, template/wheel resources, static collection and Wagtail integration. An in-process provider fixture verifies real ES256 client assertions and PKCE, and signs ES256/RS256 ID tokens with independent keys. It exercises login through Wagtail admin access, session binding, one-time state, expiry, issuer/nonce/audience/signature failures, UserInfo consistency, verified-email admission, ambiguous/inactive/ineligible accounts, safe redirects and continued local password login. Two concurrent database connections compete to consume the same callback; exactly one succeeds. Transport tests check public-address validation, pinned TLS connections, redirect refusal and bounded JSON responses. A loopback HTTPS fixture exercises the real transport with a temporary test CA, validates SNI/Host and POST encoding, and proves untrusted certificates and wrong hostnames are refused. Only tests can substitute loopback resolution and the test CA; production transport has no insecure mode.

Synthetic tests do not establish hosted-provider interoperability, browser behavior, public metadata reachability or production suitability. They use Django's test client rather than a browser engine. Before deployment, run `soca_check` against the deployed HTTPS site, complete a real SSO login, confirm Wagtail permissions, verify another browser cannot redeem a copied callback, and verify local password recovery. Review proxy/query logging and rate limits.

Provisioning tests cover the default-off boundary, explicit group selection and eligibility, a fully signed first-login callback, verified-email/allow/deny enforcement, unusable passwords and safe flags, existing-account preservation, duplicate emails and username collisions, rollback, unsupported custom models and two simultaneous first logins creating exactly one account. Provisioning settings participate in the transaction fingerprint but never appear in public metadata. Project-specific custom-user onboarding and production database configurations still require host-project testing.

Claim-inspector tests cover default-off behavior/no extra UserInfo fetch, superuser/CSRF boundaries, separate signed claims and subject-matched UserInfo, failed-login refusal, optional diagnostic fetch failures, email-fallback preservation, encryption/redaction/no profile logging, HTML escaping/no-store output, one-shot capture, stale revision protection, re-arm/clear, expiry, corrupt ciphertext and cleanup. Synthetic profile values are used: tests do not capture real users' claims.

Profile-default tests cover structured/full-name mapping, blank-only/concurrent-edit preservation, Unicode/whitespace/length validation, markup/control/type rejection, custom unique-field refusal, safe username preference/fallback/collisions, existing-identity/privilege preservation, failed-admission refusal, signed-claim precedence, optional UserInfo failures and subject/email mismatch refusal. Concurrent first-login tests deliberately use differing preferred usernames for the same email and verify that both workers resolve to one account.

For local development in an existing virtualenv:

```sh
python -m pip install -r requirements-test.txt
python -m pip install -e '.[test]'
DJANGO_SETTINGS_MODULE=tests.settings python -m django test tests
ruff check .
ruff format --check .
```

The test settings generate ephemeral fixture keys and use an isolated SQLite database. Never use them as deployment settings. Refresh dependency pins intentionally and rerun the complete container test; application/library dependencies in `pyproject.toml` use compatible ranges rather than pinning downstream projects to the test environment.
