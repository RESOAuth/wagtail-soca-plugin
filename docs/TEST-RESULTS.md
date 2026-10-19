# Test results — 0.0.1

## Release compatibility verification

The initial release PR adds Wagtail 7.4/8.0 compatibility, archive validation and hosted CI/security automation: [PR #1](https://github.com/RESOAuth/wagtail-soca-plugin/pull/1). The checks tab is authoritative for the latest commit's Python/Django/PostgreSQL/CodeQL results; historical local results below are not claims about those hosted runs.

- Local rootless Podman, Python 3.12 / Django 5.2.18 / Wagtail 7.4.3: **89 tests passed**.
- Local rootless Podman, Python 3.12 / Django 5.2.18 / Wagtail 8.0: **89 tests passed**.
- Both runs: no external test-network access, non-root user, read-only image, ephemeral writable `/tmp`; lint/formatting, system checks, migration drift, static collection, installed-wheel resources and dependency consistency passed.
- Both archive builds: wheel/sdist version and AGPL license metadata, templates, migrations, maintenance commands, package boundaries and private/generated-file checks passed.
- Workflow syntax: actionlint 1.7.12 passed. Actions and reference images are pinned to immutable commits/digests; Dependabot maintains updates.
- The existing interactive demo and its persistent data were not upgraded or reset for compatibility testing. Wagtail 8 browser-engine and real-user provider authentication are not claimed by these synthetic runs.

The additional hosted matrix tests supported Python boundaries and Django 6.0/6.1, plus PostgreSQL 17 concurrency on both Wagtail versions. Scheduled CodeQL and Dependabot version updates become active after merge to the default branch. No tag or published release is created by this PR.

The first hosted run passed all 12 CI jobs. CodeQL's initial scan identified TLS minimum-version and request-log sanitization issues in the demo/test harness; these were hardened explicitly and a TLS-minimum regression test was added (90 tests in the final suite). Final security results are available on the PR's latest commit; alerts are fixed in code, not suppressed.

## Initial build

Executed locally on 2026-10-19 with rootless Podman. The test container ran as UID 10001 with `--network=none`, `--read-only` and an ephemeral `/tmp` mount. Tests imported the installed wheel from site-packages, outside the source checkout.

Environment: Python 3.12.15, Django 5.2.18, Wagtail 7.4.3, PyJWT 2.15.1, cryptography 50.0.2 and urllib3 2.8.0. Full dependency pins are in `requirements-test.txt`.

Results:

- Container build, source distribution and wheel build: passed.
- Ruff lint and formatting: passed (32 Python files).
- Django system checks: no issues.
- Migration drift: no changes detected.
- Django test suite: **34 tests passed**, including concurrent callback consumption, real loopback TLS, ES256/RS256 tokens, admission rules and local password recovery.
- Static collection and installed-wheel templates/migrations: passed.
- Installed dependency consistency (`pip check`): no broken requirements.

Test image ID: `067b7696333f2dcce1117bbf857f621742a6bf715dd2c44995401f913d2f94bf`.

Built artifact SHA-256 values:

```text
745a71b1090548c2445d5a14683734cf516840dec8bca4f0925788ef427b9947  wagtail_soca-0.0.1-py3-none-any.whl
06803592be38bb7cd6b8c14549df9d3b33f3820ef27c27ffe1ea4fa4cde2c664  wagtail_soca-0.0.1.tar.gz
```

The identity provider is a synthetic fixture; TLS tests use a temporary CA and loopback server. No real RESOAuth end-user login, public-site deployment, browser-engine flow, PostgreSQL deployment or external security audit was performed. GitHub Actions is configured but has not been run remotely in this task. See [test instructions](TESTING.md) and [security decisions](SECURITY.md).

## RESOAuth integration update — 2026-10-19

Removed the interactive runtime identity-provider stub and its route/template/transport override. The running environment uses `https://auth.resoauth.cloud`, the plugin's default issuer. Optional Dynamic CIMD publishes inline public keys for local development without a public callback tunnel.

Final image: `16c9582cc1b2962b86660f56ff80bba5bec2188ff604d99df9844b86cf42b4ff`.

- Complete container check: **39 tests passed**, lint/formatting passed, system checks passed, no migration drift, static collection and installed wheel verified.
- Running-container check: **4 checks passed**: HTTPS/static files, password login, removed stub route (404), real RESOAuth redirect and publicly reachable matching Dynamic CIMD metadata.
- Live `soca_check`: discovery, published metadata and public key validated.
- Actual RESOAuth authorization request returned HTTP 200 and its real sign-in page: “Continue to Wagtail SOCA by confirming your email address.” No email or OTP was submitted.
- Cleared previous interactive demo sessions at cutover. Database, keys and local credentials persist in the existing volume. Logs remain accessible with `podman logs --timestamps --tail 100 wagtail-soca-demo`; previous container logs were retained in stopped containers.

Discovery does not advertise the standard CIMD support field, so the command still reports support as unconfirmed. The actual hosted authorization endpoint accepts this client through to its sign-in page. Completing a real end-user login requires configuring the intended verified administrator email and authenticating with RESOAuth; this has not been claimed as tested.

Updated artifact SHA-256 values:

```text
f938dc4706ee0a9ffd0a73a6088b880a1fff206cfa141f92cd50467766130b0d  wagtail_soca-0.0.1-py3-none-any.whl
04ed0f0aa0657224f8d326b4d6105e89a53233afa301c4d552455537443481cb  wagtail_soca-0.0.1.tar.gz
```

## Admin settings menu — 2026-10-19

Added the superuser-only **Settings → SOCA** page and applied migration `0002_socasettings` to the running environment. The persistent database, deployment key and local credentials were retained.

- Final container check: **51 tests passed**; lint/formatting, Django checks, migration drift, static collection and installed-wheel validation passed.
- New tests cover menu visibility, superuser restrictions, CSRF, validation, immediate persistence, safe secret/origin boundaries, empty admission lists, local-login recovery, stale saves, connection checks and pending-login invalidation.
- The four live HTTP/provider checks passed during rollout.
- Chromium successfully logged in locally, opened SOCA through the actual Settings menu, inspected the form and account-editor link, and ran the connection check against the real RESOAuth provider. No JavaScript errors occurred. The metadata selector fits a 390px viewport.
- The browser check did not save or alter the operator's admission rules or account email.

Final image: `0bbd12d803dc57dc96bdb19cd3a6b98840bc6fe3f15bdc08f743319ffdf35b19`.

Current artifact SHA-256 values:

```text
7563a7b126a13b57897c91554c4389a48b792361afa48c001a73a4dace5d56bb  wagtail_soca-0.0.1-py3-none-any.whl
cf2ca4ed3fa403a35026c74a2af29a848889750d3b4aa4daa77d1943e760907d  wagtail_soca-0.0.1.tar.gz
```

## Optional account creation — 2026-10-19

Added the default-off **Create accounts on first SSO login** control and explicit **New account group** choice under Settings → SOCA → Access rules. No schema migration is needed: these nonsecret policy settings use the existing settings JSON record.

- Complete isolated Podman check: **64 tests passed**, lint/formatting passed (49 Python files), Django checks passed, no migration drift, static collection and installed wheel verified.
- New coverage includes signed first-login provisioning, eligible-group validation, verified-email admission, safe flags/unusable password, existing-account preservation, duplicate/collision refusal, rollback, custom-model restrictions, policy fingerprinting and concurrent first logins creating one account.
- All **4 live demo checks passed**, including real RESOAuth authorization and matching public metadata.
- Chromium verified the native menu and new controls, available group choices, default-off state and desktop/390px selector layout. The real connection check passed with no JavaScript errors. No settings were saved by browser checks.
- Deployment retained the persistent volume. Saved-settings fingerprints matched before/after rollout, the local account count remained one, and account creation remained disabled. The previous container and logs remain available as `wagtail-soca-demo-before-provisioning`.
- New-account authentication was tested with cryptographically signed synthetic provider responses, not by registering a real RESOAuth identity. PostgreSQL and arbitrary custom-user-model onboarding remain outside this test run.

Running image: `95e6fde8f95499caa05b357cd6a4ecc3e57e0911791adeef69e7d77431abf012`.

Current exported artifact SHA-256 values:

```text
db8803147a8d4873448fa75347f3dc1e132bbc583bf08766d0b71db8a7f3e0fd  wagtail_soca-0.0.1-py3-none-any.whl
6153beb3cb1567ceae8ea0d985cd6460379f52be93089d0d8fa824523afc3721  wagtail_soca-0.0.1.tar.gz
```

## Temporary claim inspector — 2026-10-19

Added superuser-only POST/CSRF-protected arm/clear controls under Settings → SOCA. Migration `0003_claiminspection` adds one short-lived encrypted diagnostic slot. The next successful admitted SSO login can capture sanitized verified ID-token claims and subject-matched UserInfo separately; raw JWTs/access tokens are not retained or logged. Arming and captured-result visibility each last ten minutes. No account profile mapping is performed.

- Complete isolated Podman check: **74 tests passed**; lint/formatting passed (52 Python files), Django checks passed, no migration drift, static collection and installed wheel verified.
- New coverage includes default-off/no-extra-request behavior, superuser and CSRF boundaries, successful signed-callback inspection, failed-login refusal, separate claim sources, optional UserInfo failure, required email fallback, encrypted/redacted storage, no profile logging, HTML escaping/no-store, one-shot/revision protection, clear/re-arm, expiry/corruption and cleanup.
- All **4 live demo checks passed** against the updated container and real RESOAuth provider.
- Chromium verified the native inspector page and POST arm/clear/re-arm controls at desktop and 390px widths, with no JavaScript errors. It deliberately left the inspector armed for the operator's next real SSO login; no real identity claims were captured by automated checks.
- Migration applied successfully. Saved-settings fingerprints matched before/after rollout and both existing user accounts were retained. The previous container and logs remain available as `wagtail-soca-demo-before-inspector`.

Running image: `20560a29b8092979f8a1d502cf17e00aa1bc73d1b1de3dede55c7daac71f1b90`.

Current exported artifact SHA-256 values:

```text
f3cb273985e7596c5dbdc5bb390ec2f478a5a9c75519efd1e1e1797af572403a  wagtail_soca-0.0.1-py3-none-any.whl
beb0aadf74442f283607963a1700868144d8375ca8440a7a83e3f6e11065a36b  wagtail_soca-0.0.1.tar.gz
```

## Conservative profile defaults — 2026-10-19

Verified profile claims now fill blank first/last names after successful SSO admission. Existing names, usernames, emails, passwords and privileges remain authoritative. New accounts can receive validated preferred usernames, with readable email-derived and deterministic fallbacks. Missing usable profile fields may come from subject-matched, email-consistent UserInfo; optional profile retrieval does not block an otherwise valid login. No schema migration or admission-policy changes were needed.

- Complete isolated Podman check: **89 tests passed**; lint/formatting passed (54 Python files), Django checks passed, no migration drift, static collection and installed wheel verified.
- Profile coverage includes structured/full-name fallback, local/concurrent edit preservation, Unicode/whitespace/length handling, malformed/markup/control rejection, custom unique-name-field refusal, preferred usernames and collisions, existing-identity/privilege preservation, failed-admission refusal, signed-token precedence, optional UserInfo failures and identity consistency.
- Concurrent first logins deliberately supplied different preferred usernames for one email; both resolved to the same single account.
- All **4 live demo checks passed**. Chromium verified the updated guidance through the native SOCA menu, real provider connection check and narrow layout without JavaScript errors. These checks did not save configuration, profile fields or inspector controls.
- Deployment retained both local users, their existing profile state, and an identical saved-settings fingerprint. Previous container/logs remain as `wagtail-soca-demo-before-profile-defaults`.
- Profile writes were exercised with cryptographically signed synthetic provider responses. No pasted token was trusted to update a real account, and no real-provider end-user login was automated; real profiles populate on the next successful SSO login.

Running image: `484251be4624c49e7218173d86a6b111a1cff9e250bb8cf65f533a5fc097e2ff`.

Current exported artifact SHA-256 values:

```text
aad37d219df0eaa23cad19c06b7d04a448bfaa751e18ae3f94fb9502f7a50081  wagtail_soca-0.0.1-py3-none-any.whl
9dccde39018c86acdb6cca4ead32aa7d45b072d58d78a6da23e2a809e91f00e0  wagtail_soca-0.0.1.tar.gz
```
