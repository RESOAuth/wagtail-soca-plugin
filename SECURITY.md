# Security policy

Version 0.0.1 is an initial MVP, not an externally audited or certified authentication product. Keep Wagtail, Django and dependencies patched. Read the [security and deployment guide](docs/SECURITY.md) before deployment.

Report vulnerabilities privately through [GitHub private vulnerability reporting](https://github.com/RESOAuth/wagtail-soca-plugin/security/advisories/new). If private reporting is unavailable, open an issue requesting a private contact channel without including exploit details, account data, tokens or signing keys. Do not post real claim dumps or credentials in public issues or pull requests.

Security fixes target the latest plugin version. Supported framework combinations and operational limits are listed in the README. Retain a working local administrator password, configure explicit admission rules and ingress rate limits, and redact OAuth query strings in infrastructure logs.
