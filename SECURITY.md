# Security Policy

## Supported versions

| Version | Supported |
| --- | --- |
| 1.x | ✅ |

## Reporting a vulnerability

Please do **not** open a public issue for security vulnerabilities. Report
privately instead:

- Open a [private security advisory](https://github.com/banyan87/dsh-full-lan-access/security/advisories/new) on GitHub (preferred), or
- Email the repository maintainers (address listed on the GitHub profile).

Include, if possible:

- the affected version(s),
- a minimal reproduction,
- the impact you believe the flaw has,
- a suggested fix (optional).

You should receive an acknowledgment within 5 business days. We will work
with you to validate the report, and we will credit you for the discovery
(unless you prefer to stay anonymous).

## Security-relevant behaviors

- The gateway fails closed: missing/malformed `passwordHash` with
  `requireAuth` prevents startup.
- Passwords are hashed with scrypt (N=16384, r=8, p=1); the hash format is
  `scrypt$N$r$p$salt$hash`. The hash string itself is a credential — protect
  `$DSH_HOME`.
- Session tokens are 256-bit random values; only their SHA-256 digests are
  persisted.
- Proxy headers are never trusted and are rejected by default.
- See [docs/security.md](docs/security.md) for the full model.
