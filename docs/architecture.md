# Architecture

```
                    LAN clients (phones, laptops, other machines)
                                   │
                                   ▼
                ┌─────────────────────────────────────────┐
                │   Gateway (this plugin, own listener)    │
                │   http(s)://0.0.0.0:3081                 │
                │                                           │
                │  1. real socket address                   │
                │  2. proxy-header check ──reject→ 400      │
                │  3. CIDR policy ────────deny→ 403         │
                │  4. loopback? ────────yes→ skip auth      │
                │  5. /__lan_gate/* routes (login/logout/   │
                │     status, CSRF, rate limiting)          │
                │  6. session cookie valid? ──no→ 302/401   │
                │  7. general rate limit ────over→ 429      │
                │  8. stream proxy (HTTP) / tunnel (WS)     │
                └──────────────────┬────────────────────────┘
                                   │ 127.0.0.1:3080 (HTTP/WS)
                                   ▼
                ┌─────────────────────────────────────────┐
                │   DSH web server (untouched)             │
                │   webServer service routes + SPA dist    │
                └─────────────────────────────────────────┘
```

## Components

| Module | Responsibility |
| --- | --- |
| `lib/index.js` | Cordis plugin entry: `lanAccess` `Service`, Config schema, lifecycle, local status route on the DSH `webServer` |
| `lib/server.js` | The gateway: request/upgrade pipeline, HTTP(S) listener, TLS material, session handling |
| `lib/proxy.js` | Streaming HTTP reverse proxy + raw TCP WebSocket tunnel to the upstream |
| `lib/policy.js` | Pure request-policy helpers (client IP, proxy headers, cookies, forwardable headers) |
| `lib/cidr.js` | Dependency-free IPv4/IPv6 CIDR parser and matcher |
| `lib/scrypt.js` | `scrypt$N$r$p$salt$hash` hashing and constant-time verification |
| `lib/sessions.js` | Session store: tokens → SHA-256 digests, TTL, eviction, JSON persistence |
| `lib/ratelimit.js` | Sliding-window per-key rate limiter |
| `lib/audit.js` | JSON-lines audit logger |
| `lib/login.js` | Self-contained login page + CSRF tokens |
| `lib/x509.js` | Dependency-free self-signed X.509 v3 certificate generation |
| `lib/config.js` | Defaults, deep merge, fail-closed validation, sanitized status view |
| `bin/dsh-lan-gate.js` | Operator CLI (`hash-password`, `verify`, `cidr`, `check-config`) |

## Request flow (HTTP)

1. **Source of truth.** The client address is always `req.socket.remoteAddress`,
   normalized (IPv4-mapped forms collapse to IPv4). Proxy headers are never
   consulted; with `rejectProxyHeaders: true` their presence alone yields
   `400`.
2. **IP policy.** `denyCidrs` is evaluated first (deny wins), then
   `allowCidrs`; anything else gets `403`. Policy decisions are audited.
3. **Loopback bypass.** If `loopbackBypassAuth` and the client is on
   loopback, the request is proxied immediately (subject to the general rate
   limit if enabled).
4. **Gateway-local routes.** `/__lan_gate/login` (GET page with a CSRF
   double-submit cookie, POST verify with per-IP rate limiting),
   `/__lan_gate/logout`, `/__lan_gate/status` (requires auth in auth mode).
5. **Session check.** A valid `dsh_lan_session` cookie (HttpOnly, SameSite=Lax,
   Secure under TLS) passes; otherwise browsers get a `302` to the login page,
   API-style requests get `401` JSON.
6. **Rate limit.** Non-loopback clients are throttled per IP.
7. **Proxy.** Headers are sanitized (hop-by-hop and gateway cookies
   stripped), the `Host` header is reset to the upstream, and the request and
   response bodies are streamed without buffering. Timeouts yield `502`.

## Upgrade flow (WebSocket)

The `upgrade` event runs the same address/policy/auth checks **before** any
byte is tunneled. Authenticated upgrades are forwarded over a raw TCP
connection: the gateway rebuilds the upgrade request with sanitized headers
and pipes the socket both ways, so DSH's WebSocket RPC channel works
unchanged.

## Sessions

- Tokens: 32 random bytes, hex, returned once at login in the cookie.
- Persistence: only `sha256(token)` + expiry in `<stateDir>/sessions.json`
  (atomic write via temp file + rename). A leaked state file cannot be
  replayed as a session.
- Verification re-hashes the presented token, so sessions survive gateway
  restarts. Expired sessions are pruned lazily; `maxSessions` evicts the
  oldest.

## TLS

- `tls.enabled` with `certPath`/`keyPath` uses your certificates.
- Without paths, a self-signed ECDSA P-256 certificate is generated with a
  minimal DER encoder (no OpenSSL dependency), SAN-listed for `localhost`,
  loopback, and every non-internal interface address, and persisted under
  `<stateDir>/tls/` (key with `0600` where supported). The test suite proves
  the certificate passes a full Node TLS handshake with `rejectUnauthorized:
  true` when trusted as a root.
- Clients will still see the usual self-signed warning; either install the
  certificate or use a trusted CA (e.g. via `certPath`/`keyPath`).

## Fail-closed startup

`resolveConfig` throws before the listener binds when:
- a CIDR string is invalid,
- `requireAuth: true` but `passwordHash` is missing or malformed,
- ports are out of range, `upstream.protocol` is invalid, or audit levels are
  unknown.

In a DSH profile the failing row is reported by the loader and startup is
rejected — the gateway never starts half-configured.

## Status surface

- `GET /__lan_gate/status` on the gateway (auth-protected in auth mode).
- `GET /__lan_gate/status` on the DSH web server itself (loopback only,
  registered through `webServer.register`), so the host can query the gateway
  without knowing its port.
- The `lanAccess` Cordis service: `status()`, `sessions()`,
  `revokeSession(token)`, `revokeSessionById(id)`.

The status payload never includes the password hash.
