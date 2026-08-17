# Security

This document states the security model of `dsh-full-lan-access`, what is
defended against, and how to operate it safely.

## Model

The gateway is a **separate, explicitly-trusted perimeter** in front of the
DSH web server. The DSH server itself stays bound to `127.0.0.1`; nothing
about DSH's own exposure changes. Every byte that reaches DSH through the
gateway has passed: IP policy → (loopback bypass) → authentication → rate
limit → header sanitization.

## Trust boundaries

| Boundary | Trust |
| --- | --- |
| DSH host loopback | Fully trusted (bypasses auth by default) |
| CIDR-allowlisted LAN clients with a valid session | Trusted with DSH's own capabilities |
| CIDR-allowlisted LAN clients without a session | Not trusted (login required) |
| Everything else | Not trusted (403/400) |

## Defenses

### 1. Never trust the socket's story
- The client address comes exclusively from the kernel socket
  (`req.socket.remoteAddress`).
- Spoofable headers (`X-Forwarded-For`, `X-Real-IP`, `Forwarded`, `Via`,
  `X-Client-IP`, …) are **ignored** and, by default, rejected outright
  (`rejectProxyHeaders: true`). A LAN attacker cannot whitewash its address.

### 2. Password verification
- scrypt with OWASP-recommended interactive-login parameters
  (N=16384, r=8, p=1, 16-byte salt, 32-byte key), encoded as
  `scrypt$N$r$p$salt$hash`.
- Constant-time comparison (`timingSafeEqual`); malformed hashes fail closed.
- Per-IP sliding-window attempt limiting with lockout messaging; the general
  per-IP throttle bounds traffic from misbehaving clients.
- CSRF double-submit protection on the login form; login responses are
  `Cache-Control: no-store`.

### 3. Sessions
- 256-bit random tokens, delivered once as `HttpOnly; SameSite=Lax`
  cookies (`Secure` under TLS).
- Only SHA-256 digests are persisted — a leaked `sessions.json` is not
  replayable.
- TTL (default 7 days), maximum concurrent sessions with oldest-first
  eviction, server-side revocation via the `lanAccess` service.
- The gateway's session cookies are stripped before proxying, so they never
  leak to the upstream or into DSH's own logs.

### 4. The proxy
- Streaming only — request/response bodies are never buffered.
- Hop-by-hop headers and the gateway's cookies are removed; `Host` is reset
  to the upstream.
- WebSocket upgrades are authenticated before any tunneling begins.
- Upstream timeouts produce `502` instead of hanging connections.

### 5. Audit
Every security-relevant decision is emitted as one JSON line: IP allowed /
denied, proxy header rejection, auth success / failure / lockout, CSRF
rejection, rate limiting, proxy errors, startup/shutdown. Configure
`audit.file` for durable records and monitor them.

## Operational hardening checklist

- [ ] Use a strong, unique password; rotate it and restart the gateway.
- [ ] Keep `allowCidrs` as narrow as your network needs; add
      `denyCidrs` for known-bad devices.
- [ ] Enable `tls.enabled` if your network is untrusted, and prefer
      `certPath`/`keyPath` from a CA you control; otherwise use the
      auto-generated self-signed certificate and distribute it to clients.
- [ ] Protect `$DSH_HOME` (and `stateDir`) — they contain the password hash,
      session digests, and TLS keys. Restrict read access to the DSH user.
- [ ] Point `audit.file` somewhere persistent and alert on `auth-failed` /
      `rate-limited` / `ip-denied` storms.
- [ ] Consider OS-level firewall rules that permit only the gateway port
      (default 3081) from the allowlisted ranges and deny everything else.
- [ ] `loopbackBypassAuth: false` when the host itself is shared or
      untrusted.

## Known limitations

- The login page ships in English; there is no account system — one shared
  password gates the gateway (matches the DSH single-user model).
- Self-signed TLS is not a substitute for a real CA in untrusted networks;
  it only prevents casual eavesdropping once clients pin/trust the cert.
- The gateway cannot protect against an attacker who already has an
  authenticated session (by design — it is an access gate, not an
  authorization layer inside DSH).
- Sessions are process-local (in-memory digests mirrored to disk); a full
  redeploy that wipes `stateDir` invalidates all sessions (users simply
  log in again).

## Reporting a vulnerability

See [SECURITY.md](../SECURITY.md).
