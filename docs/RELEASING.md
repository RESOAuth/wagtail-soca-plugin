# Release checklist

1. Verify the package and `wagtail_soca.__version__` agree; update the changelog and supported-version documentation.
2. Require a green PR: installed-wheel compatibility tests, both Podman variants, PostgreSQL concurrency tests, and Python/Actions CodeQL analysis. Review security alerts, not only job exit codes.
3. Build a clean source distribution and wheel. Check archive contents, metadata, license, templates and migrations with `python tests/verify_distribution.py dist`. CI retains reviewed artifacts for 14 days.
4. Complete a real SSO login in a safe environment and check permissions, provisioning, blank-only profile defaults, local password recovery and logs. Synthetic CI does not authenticate an actual person or certify a deployment.
5. Confirm cleanup scheduling, trusted HTTPS/proxy configuration, rate limits, persistent keys/secrets, backup/retention policies and the ten-minute diagnostic-inspector lifetime.
6. After review and merge, create an annotated version tag and GitHub release deliberately. Publish only the reviewed artifacts through the project's chosen trusted publishing process. No publishing credentials belong in this repository.

Maintainers should enable private vulnerability reporting, Dependabot security updates and branch/ruleset checks in repository settings. Dependabot version updates and scheduled CodeQL runs become active when their configuration lands on the default branch. Do not enable both default and advanced CodeQL setup for the same language; this repository provides an advanced workflow. Ruleset/security-setting changes and release publication are separate from creating the release PR.
