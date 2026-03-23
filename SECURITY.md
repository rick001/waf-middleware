# Security policy

## Supported versions

| Version | Supported          |
| ------- | ------------------ |
| 1.x     | Yes                |
| &lt; 1.0 | No (upgrade to 1.x) |

## Reporting a vulnerability

Please **do not** open a public GitHub issue for security reports.

1. Email the maintainer (see repository owner / `package.json` `author`) with:
   - Description of the issue and impact
   - Steps to reproduce (if safe to share)
   - Affected version(s)

2. Allow a reasonable time for triage and fix before public disclosure.

## Scope

This package is **request hardening middleware**, not a complete WAF or replacement for:

- Parameterized database queries
- Output encoding / CSP / HTML sanitization at render time
- Authentication, rate limiting, or edge DDoS protection

See [README.md](./README.md).

## Supply chain

- Run `npm audit` in consuming applications.
- Pin versions in production lockfiles.
