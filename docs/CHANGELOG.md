# Changelog

## 0.0.1 — initial release candidate

First alpha MVP, supporting Wagtail 7.4 LTS and 8.0. No external security audit is claimed.

### Added

- Wagtail admin SSO with RESOAuth by default, compatible OpenID Connect providers, self-hosted or proxied CIMD metadata and public JWKS.
- Authorization code flow with PKCE S256, ES256 `private_key_jwt`, explicitly pinned ES256/RS256 ID-token verification and subject-matched UserInfo.
- Verified-email allow/deny admission, existing local permission enforcement, encrypted one-use browser-bound transactions, safe local redirects and continued local password login.
- Superuser-only **Settings → SOCA**: provider/metadata options, admission rules, stale-save protection, connection checks, public client/callback details and local-login recovery. Deployment keys and origin remain server-managed.
- Opt-in account creation into an explicitly chosen Wagtail group, unusable local passwords, safe privilege flags and concurrent-login protection.
- Blank-only profile defaults from verified given/family/full names, new-account preferred usernames with safe fallbacks, and preservation of existing local edits, identities and permissions.
- Explicitly armed, one-shot claim inspection for superusers, with redaction, encryption, ten-minute expiry and immediate clearing. Raw tokens are never retained or logged.
- Configuration checks and `soca_check`/`soca_cleanup` commands, installable wheel/sdist, archive verification and a persistent loopback-only HTTPS Podman demo using the real provider.
- PR CI for both Wagtail versions, representative Python/Django combinations, installed-wheel resources and PostgreSQL concurrency; SHA-pinned actions, weekly Dependabot updates and Python/Actions CodeQL scans.

### Boundaries

One provider and application-wide admission policy; no public registration, arbitrary role mapping, automatic login redirects, provider logout or overlapping signing-key rotation. Custom-user onboarding and production deployment settings require project-specific review. This PR does not publish or tag a release.
