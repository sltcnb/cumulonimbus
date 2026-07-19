# Security Policy

## Supported versions

Cumulonimbus is pre-1.0 (`0.x`). Security fixes are applied to the latest
released version and the `main` branch only.

| Version | Supported |
|---------|-----------|
| 0.1.x   | ✅        |
| < 0.1   | ❌        |

## Reporting a vulnerability

**Please do not open a public issue for security problems.**

Report vulnerabilities privately via GitHub Security Advisories:

1. Go to the [Security tab](https://github.com/sltcnb/cumulonimbus/security/advisories).
2. Click **Report a vulnerability**.

Alternatively, open a minimal issue asking a maintainer to contact you and we
will arrange a private channel.

Please include:

- A description of the vulnerability and its impact.
- Steps to reproduce (a minimal proof-of-concept is ideal).
- Affected version(s) and environment.

We aim to acknowledge reports within **72 hours** and to provide a remediation
timeline after triage.

## Scope and handling notes

Cumulonimbus processes forensic evidence and talks to cloud provider APIs.
When reporting, please keep the following in mind:

- **Do not** include real customer data, live credentials, or non-redacted
  logs in reports.
- Collectors are **read-only** by design; report any code path that mutates
  cloud state as a security issue.
- Credentials are never logged or written to output; report any leak of
  secrets into logs, error messages, or output artifacts.
