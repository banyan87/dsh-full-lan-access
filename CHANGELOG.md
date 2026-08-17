# Changelog

All notable changes to dsh-full-lan-access are documented here. The format
is based on [Keep a Changelog](https://keepachangelog.com/), and the project
adheres to [Semantic Versioning](https://semver.org/).

## [1.0.0] — 2026-08-17

Initial release.

### Added

- **Gateway** — dedicated listener (`0.0.0.0:3081` by default) that
  reverse-proxies to the DSH web server (`127.0.0.1:3080` by default),
  including WebSocket upgrade tunneling.
- **IP policy** — IPv4/IPv6 CIDR allowlist and denylist (deny wins),
  IPv4-mapped address normalization, loopback detection. Dependency-free
  matcher (`lib/cidr.js`).
- **Authentication** — scrypt password hashing with OWASP-style parameters
  in the `scrypt$N$r$p$salt$hash` format, constant-time verification,
  CSRF-protected login page, per-IP login attempt limiting with lockout.
- **Sessions** — 256-bit random tokens, SHA-256 digest persistence, TTL,
  max-session eviction, revocation API, restart survival.
- **Loopback bypass** — localhost clients skip authentication by default.
- **Proxy-header rejection** — `X-Forwarded-*`/`Forwarded`/`X-Real-IP`/`Via`
  are never trusted and rejected by default.
- **TLS** — optional HTTPS with external certificates, or dependency-free
  auto-generated self-signed ECDSA certificates persisted under the state
  directory.
- **Rate limiting** — optional general per-IP request throttle.
- **Audit logging** — JSON-lines events for every security decision, to the
  DSH logger and/or a file.
- **Status surface** — `GET /__lan_gate/status` on the gateway and on the
  DSH web server; `lanAccess` Cordis service (`status`, `sessions`,
  `revokeSession`, `revokeSessionById`).
- **Operator CLI** — `dsh-lan-gate hash-password`, `verify`, `cidr`,
  `check-config`.
- **Fail-closed validation** — invalid CIDRs, missing/malformed password
  hashes, and bad port ranges prevent startup with clear errors.
- **Tests** — 64 unit + integration tests (node:test): CIDR, scrypt,
  sessions, rate limiting, policy, X.509 (validated via a full TLS
  handshake), the complete gateway pipeline, and the Cordis plugin contract
  (Service lifecycle, loader composition).
- **Documentation** — bilingual READMEs, architecture, configuration,
  security model, API reference, troubleshooting, and a security policy.
