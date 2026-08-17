# Changelog

All notable changes to dsh-full-lan-access are documented here. The format
is based on [Keep a Changelog](https://keepachangelog.com/), and the project
adheres to [Semantic Versioning](https://semver.org/).

## [1.3.0] — 2026-08-17

### Added

- **Browser-based directory picker pinned by the bundle.** DSH's adaptive
  picker resolves to the native OS chooser on desktop hosts, but a native
  dialog can only open on the host machine — workspace creation from a LAN
  browser was broken. The bundle now disables the `directory-picker` (auto)
  row and composes the `browse` pair directly
  (`dsh-host-directory-picker-browse` + `dsh-client-ui-directory-picker-browse`),
  the documented way to pin the interaction. The web file browser works
  from any browser, local or remote. Opt out by re-enabling the rows from
  the profile's own patch layer (see `cordis.patch.yml`).
- **Reachability diagnostics** — the gateway logs and exposes on
  `/__lan_gate/status` (`urls`) every non-internal interface address with
  the bound port, so the URL a LAN/VPN client should open is visible at a
  glance (e.g. `http://172.16.1.36:3081`).

## [1.2.0] — 2026-08-17

### Added

- **Browser-compatibility layer (`compat` config)** so the DSH web client
  works over plain-HTTP LAN origins:
  - `injectRandomUUIDPolyfill` — injects a `crypto.randomUUID()` polyfill
    (backed by `crypto.getRandomValues`) into HTML pages before `</head>`.
    Browsers only expose `crypto.randomUUID` in secure contexts, so the
    DSH client's direct calls (workspace creation, model page, plugin
    pages) threw `crypto.randomUUID is not a function` on LAN origins.
  - `rewriteOrigin` — rewrites the `Origin` header of proxied requests
    (HTTP and WebSocket upgrades) to the upstream authority so DSH's
    `/api` trust fence (Origin must match Host) passes. Without it every
    request carrying an Origin was rejected with 403, breaking privileged
    RPCs such as `settings.*` (language preference), the plugin inventory,
    and model discovery for LAN clients.
  - Both default to `true` and are independently disableable.

### Changed

- `lib/compat.js` extracted for the polyfill/injection helpers; the proxy
  buffers only injectable HTML (≤ 512 KB, identity-encoded) and streams
  everything else untouched; `Content-Length` is dropped for injected
  responses.

### Added (tests)

- `test/compat.test.js` (injection anchors, content-type/encoding rules).
- Gateway integration tests: HTML injection through the proxy, Origin
  rewriting for HTTP and WebSocket upgrades, and both compat switches off.

## [1.1.1] — 2026-08-17

### Fixed

- **General rate limit no longer throttles authenticated sessions.** The
  per-IP limiter previously counted every non-loopback request, so the DSH
  web UI's bursty page loads (dozens of bundle/asset requests per load)
  exhausted the 120 req/min budget, produced `429` storms, and triggered
  browser retry loops. The limiter now applies only to **unauthenticated**
  non-loopback traffic — it guards the auth gate and the upstream from
  anonymous floods, while authorized sessions and loopback traffic flow
  freely. The login-attempt limiter is unchanged.
- **Request timeout no longer kills long-lived upstream streams.** The
  upstream timeout applied to socket idleness, so DSH's SSE event channels
  (which legitimately stay open without data) were torn down after
  `proxy.timeoutMs`, surfacing as `proxy-error: upstream timeout`. The
  timeout now guards only the request phase and is cleared once upstream
  response headers arrive.

### Added

- Tests for the new semantics: unauthenticated traffic is rate-limited,
  authenticated traffic is exempt, and SSE-style streams survive the
  request timeout.

## [1.1.0] — 2026-08-17

### Added

- **Profile bundle registration** — the package manifest now declares
  `dsh.bundle.patch` (`cordis.patch.yml` at the package root), so
  `dsh plugin --profile web add dsh-full-lan-access` registers the plugin as
  a composition layer and inserts the `lan-access` row automatically. Users
  only override the row's config (e.g. `passwordHash`) from their own
  `cordis.patch.yml`; the row identity is inherited from the bundle.
- **Bundle contract tests** (`test/bundle.test.js`) — pins the patch
  semantics (id-targeted per-key merge, wholesale `config` replacement,
  `insert` lists), the fail-closed unconfigured row, and the configured
  override booting and proxying through the loader.

### Changed

- **Fail-closed install flow** — the bundle row ships with no config on
  purpose: the first boot after `dsh plugin add` without a configured
  `passwordHash` fails loudly with an actionable error instead of exposing
  an unauthenticated gateway.
- **Installation docs** — rewritten around the bundle flow; documents the
  manual `insert:` flow for plain (non-bundle) installs and why a bare
  `- id:` patch is skipped when the row does not exist.
- **Example patch** — now uses the correct `insert:` form
  (`examples/cordis.patch.example.yml`).

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
