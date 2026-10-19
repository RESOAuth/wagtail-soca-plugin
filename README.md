# Simple OAuth CIMD Access for Wagtail

[![CI](https://github.com/RESOAuth/wagtail-soca-plugin/actions/workflows/ci.yml/badge.svg)](https://github.com/RESOAuth/wagtail-soca-plugin/actions/workflows/ci.yml)
[![CodeQL](https://github.com/RESOAuth/wagtail-soca-plugin/actions/workflows/codeql.yml/badge.svg)](https://github.com/RESOAuth/wagtail-soca-plugin/actions/workflows/codeql.yml)

SOCA adds OpenID Connect single sign-on to the Wagtail admin using an OAuth Client ID Metadata Document (CIMD). Version **0.0.1** is a lean MVP inspired by [the WordPress SOCA plugin](https://github.com/RESOAuth/wordpress-soca-plugin). It defaults to the RESOAuth issuer and supports compatible providers.

It publishes client metadata and a public signing key, uses authorization code with PKCE S256 and ES256 `private_key_jwt`, and validates signed ES256 or RS256 ID tokens. A verified email must pass explicit admission rules and match exactly one active local account with Wagtail admin access. Optional first-login account creation is off by default and requires a chosen Wagtail group. Verified profile claims fill blank names, preserving local edits and existing usernames, emails and permissions. The [interactive Podman environment](demo/README.md) connects directly to `auth.resoauth.cloud`.

Version **0.0.1** is an alpha MVP; review the [security guide](docs/SECURITY.md) before deployment. Licensed under [AGPL-3.0-only](LICENSE).

## Compatibility

| Wagtail | Django | Python |
| --- | --- | --- |
| 7.4 LTS | 5.2 | 3.10–3.14 |
| 7.4 LTS | 6.0 | 3.12–3.14 |
| 8.0 | 5.2 | 3.10–3.14 |
| 8.0 | 6.0 or 6.1 | 3.12–3.14 |

CI tests representative combinations at the Python compatibility boundaries, both Wagtail lines in Podman, and SQLite/PostgreSQL. It installs and tests the built wheel outside the checkout. See [testing](docs/TESTING.md) for exact coverage and [recorded local results](docs/TEST-RESULTS.md). A compatible version range is not a claim that future, unreleased framework versions have been tested.

## Install

Install from this checkout with `pip install .`, or build and install a wheel:

```sh
python -m pip install build
python -m build
python -m pip install dist/wagtail_soca-0.0.1-py3-none-any.whl
```

Put `wagtail_soca` **before** `wagtail.admin` in `INSTALLED_APPS` so its login template is found. Keep `django.contrib.auth.backends.ModelBackend` in `AUTHENTICATION_BACKENDS`. Include the public URLs before any catch-all Wagtail page route:

```python
from django.urls import include, path

urlpatterns = [
    path("soca/", include("wagtail_soca.urls")),
    # Existing admin, document and page URL patterns follow.
]
```

Generate one persistent P-256 private key in your deployment's protected secret storage (outside the repository):

```sh
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out /protected/secrets/soca.pem
chmod 600 /protected/secrets/soca.pem
```

Configure Django, adapting the origin and allowed addresses:

```python
from pathlib import Path

SESSION_COOKIE_SECURE = True
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = "Lax"
CSRF_COOKIE_SECURE = True

SOCA = {
    "ENABLED": True,  # Initial default; editable through Settings → SOCA.
    "BASE_URL": "https://cms.example.com",  # Origin only, no trailing slash.
    "ISSUER": "https://auth.resoauth.cloud",
    "PRIVATE_KEY": Path("/protected/secrets/soca.pem").read_text(),
    "ALLOW_EMAILS": ["editor@example.com"],
    "ALLOW_DOMAINS": [],
    "DENY_EMAILS": [],
    "DENY_DOMAINS": [],
    "CREATE_USERS": False,  # Opt in through Settings → SOCA.
    "NEW_USER_GROUP": None,  # Required group primary key when CREATE_USERS is True.
    "ID_TOKEN_ALG": "ES256",  # Or RS256; explicitly pinned, no fallback.
    "ASSERTION_AUDIENCE": "issuer",  # Or token_endpoint, per provider requirements.
}
```

Use server-side Django sessions (the default database backend is suitable). Signed-cookie sessions are refused. Configure trusted reverse-proxy HTTPS handling in the host project. The origin is explicit and never taken from a request's Host header. URL prefixes mounted through Django are supported; `BASE_URL` remains the origin.

```sh
python manage.py migrate
python manage.py check
python manage.py soca_check
```

Sign in locally as a Wagtail superuser and open **Settings → SOCA**. Configure the provider, client metadata mode and exact email/domain admission rules, then save. Settings apply immediately and are shared across all Wagtail sites in this installation. The form starts with the `SOCA` deployment defaults; after the first save, the database-backed admin settings take precedence for the fields exposed in the form. The site origin and private signing key remain deployment-managed and are never stored in admin settings.

## Access rules and profile defaults

Under **Access rules**, use **Edit your Wagtail account** or **manage users** to set the local account email to the verified address used at your provider, and add the corresponding allow rule. Empty allow lists deny all SSO access. **Check connection** validates the saved discovery/metadata/public keys; **Test SSO login** starts a real sign-in. Saving settings invalidates pending SSO transactions, and stale forms cannot overwrite a newer save. Local password login remains available when SSO is disabled.

To create accounts automatically, turn on **Create accounts on first SSO login** under Access rules and select a **New account group**, then save. Only groups with Wagtail admin access are listed. Choose the least-privileged suitable group: every new verified, admitted email receives that group's permissions. New accounts have an unusable local password and no Django staff/superuser flags. Existing users are never promoted, re-enabled or moved into the group; ambiguous emails still fail closed. Turning creation off does not delete accounts already created. Compatible custom user models are supported with the restrictions in the [security guide](docs/SECURITY.md).

After successful SSO admission, `given_name` and `family_name` fill blank `first_name` and `last_name` fields. Existing names are preserved, including against concurrent local edits. If only `name` is available and both local fields are blank, the whole full name becomes `first_name`; the plugin does not guess surname boundaries. Strings are normalized, validated and bounded to the local field length; invalid types, markup and control characters are ignored. Signed ID-token profile claims take priority; missing usable values can come from subject-matched, email-consistent UserInfo. Optional profile retrieval failures do not block a valid sign-in. New users get a valid, available `preferred_username`, otherwise an email-local-part plus short hash, with a deterministic `soca_` identifier as a final fallback. Existing usernames are never renamed. Profile claims never select an account or grant permissions. Avatar downloads, locale/preferences and arbitrary custom-field mapping are not performed.

For profile-mapping diagnostics, superusers can open **Temporary claim inspector** on the same page and click **Inspect next SSO login**. This explicitly arms a site-wide, one-shot capture of the next successful, admitted SSO login, not necessarily the administrator's own login. It expires after ten minutes. The report separates verified ID-token claims from subject-matched UserInfo and expires ten minutes after capture. Known profile/basic identity values are visible; protocol secrets and unknown claim values are redacted while claim names remain discoverable. Raw JWTs/access tokens are never retained or logged. Reports are encrypted in the database, inaccessible after expiry, and removed on the next inspector access or `soca_cleanup` run. Clear the report when finished. A non-superuser can complete the test login; sign back in with a local superuser to view the report. Inspection does not populate or update account profile fields.

## Metadata and provider checks

`soca_check` fetches provider discovery and the public documents through HTTPS. Your site and the provider must be reachable through public DNS with trusted TLS certificates. A document check does not prove successful provider authentication: complete a real login before rollout. CIMD support missing from discovery is unconfirmed; explicitly false is refused.

For local HTTPS development, set `"METADATA_PROXY": "https://dynamic-cimd.resoauth.cloud/cimd/%s"` in `SOCA`. This encodes the public client metadata and public signing key in a publicly reachable URL, as in the WordPress plugin. RESOAuth can fetch that URL while redirecting the browser back to your local callback. The proxy is a metadata service, not an identity provider. No private key, policy list or user email is included. The generated URL is immutable; changing public metadata or keys changes the client ID. Without this setting the package uses self-hosted metadata.

With the sample URL configuration, the client ID is `https://cms.example.com/soca/client.json`, public keys are at `/soca/jwks.json`, and the callback is `/soca/callback/`. The provider must accept that metadata URL as the client ID. The Wagtail login screen gains **Continue with SSO** alongside the password form.

## Operations and boundaries

Admission is denied by default when both allow lists are empty. Rules match exact, case-insensitive ASCII emails/domains, without wildcards or implicit subdomains; deny rules win. A provider that can verify an admitted administrator email can access that administrator's account. Review provider trust and retain a local administrator password.

Run `python manage.py soca_cleanup` regularly, for example hourly, to remove expired login transactions. Apply rate limits to `/soca/login/` and `/soca/callback/` at your ingress. Redact callback query strings in proxy/access logs and error monitoring. See [security and deployment decisions](docs/SECURITY.md).

This MVP has a superuser-only settings menu, optional admitted-user provisioning into one selected group, one provider, self-hosted or proxied metadata, one externally managed signing key and local Django logout. Key rotation requires a maintenance window; see the security guide. Public registration, arbitrary claim-to-role mapping, automatic login redirects, automatic key rotation and provider logout are outside version 0.0.1. Automated tests do not complete a real end-user login.

## Podman test

```sh
podman build -t wagtail-soca-test:0.0.1 -f Containerfile .
podman run --rm --network=none --read-only \
  --tmpfs /tmp:rw,nosuid,nodev,size=256m wagtail-soca-test:0.0.1
```

The image builds the sdist and wheel, installs the wheel and runs Django/Wagtail integration tests as an unprivileged user. The test run has no external network access and uses ephemeral storage. The same commands run in GitHub Actions. See [testing](docs/TESTING.md) and [release history](docs/CHANGELOG.md).

To check Wagtail 8, build a separate image with `--build-arg WAGTAIL_VERSION=8.0`; keep the running demo's image/volume unchanged. The Wagtail 7.4 reference environment uses `requirements-test.txt`; the Wagtail 8 variant resolves its additional compatible dependencies.

## Project maintenance

PRs run CI and CodeQL without deployment secrets. GitHub Actions are pinned to immutable commits; Dependabot checks Python dependencies, actions and container images weekly. Security checks are not an external audit. See [contributing](CONTRIBUTING.md), [security reporting](SECURITY.md) and the [release checklist](docs/RELEASING.md). Creating the 0.0.1 PR does not publish a package or release.
