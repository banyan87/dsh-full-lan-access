# dsh-full-lan-access

Secure LAN access for [DeepSeek Harness](https://github.com/deepseek-ai/deepseek-harness) (DSH). A drop-in Cordis plugin that opens a **guarded gateway** on your LAN and reverse-proxies to the DSH web UI — with CIDR allowlists, password authentication (scrypt), session tokens, brute-force rate limiting, optional TLS, WebSocket tunneling, and a JSON-lines audit log.

> ⚠️ **Security first.** The DSH web server itself stays bound to `127.0.0.1`. This plugin never exposes it raw: every LAN request must pass the gateway's IP policy and — for non-loopback clients — a password login before it is streamed to DSH.

## Features

| Capability | Details |
| --- | --- |
| 🛡️ IP allowlist / denylist | IPv4 + IPv6 CIDR matching; deny rules always win; IPv4-mapped addresses normalized |
| 🔑 Password authentication | scrypt hashing (`scrypt$N$r$p$salt$hash`, OWASP-style defaults), constant-time verification, CSRF-protected login form |
| 🎟️ Session tokens | 256-bit random tokens, SHA-256 digests only (tokens never persisted), TTL + max-session eviction, survives gateway restarts |
| 🚦 Rate limiting | per-IP login attempt limiting with lockout, plus optional general per-IP throttling |
| 🔒 Loopback bypass | localhost clients pass straight through (configurable) — `http://127.0.0.1:3081` stays frictionless |
| 🚫 Proxy-header rejection | `X-Forwarded-For` / `X-Real-IP` / `Forwarded` / `Via` etc. are never trusted and are actively rejected by default |
| 🔐 TLS | optional HTTPS with your own cert/key, or dependency-free auto-generated self-signed ECDSA certificates (persisted under the state dir) |
| 🔌 WebSocket proxy | DSH's client RPC WebSocket is tunneled after the same authentication checks |
| 📜 Audit log | JSON-lines audit of allow/deny/auth/rate-limit/proxy events, to the DSH logger and/or a file |
| 🧰 Operator CLI | `dsh-lan-gate hash-password`, `verify`, `cidr`, `check-config` |
| 🩺 Status API | `GET /__lan_gate/status` (also registered on the DSH web server itself) |
| 🧩 DSH-native | a Cordis `Service` (`lanAccess`) with lifecycle, Config schema, fail-closed startup validation, and loader-entry compatibility |

## Quick start

```bash
# 1. Install into the web profile (forwards to pnpm)
dsh plugin --profile web add dsh-full-lan-access

# 2. Generate a password hash
npx dsh-lan-gate hash-password            # prompts; or pass the password as an argument

# 3. Add the row to $DSH_HOME/profiles/web/cordis.patch.yml
#    (see examples/cordis.patch.example.yml)

# 4. Restart dsh web, then open http://<your-lan-ip>:3081 from another device
```

From the LAN, unauthenticated browsers are redirected to the gateway's login page; authenticated clients are proxied to the DSH web UI, including WebSocket connections. From the DSH host itself, `http://127.0.0.1:3081` requires no login (loopback bypass).

## Documentation

- [Installation](docs/installation.md) — dsh plugin integration, cordis.yml rows, verification
- [Configuration](docs/configuration.md) — every option, with defaults
- [Architecture](docs/architecture.md) — components, request flow, threat model
- [Security](docs/security.md) — security model, hardening, known limitations
- [API](docs/api.md) — gateway endpoints, cookies, status payload
- [Troubleshooting](docs/troubleshooting.md) — common problems
- [SECURITY.md](SECURITY.md) — reporting vulnerabilities

## Development

```bash
npm install          # dev dependencies (@deepseek-ai/cordis, schemastery, loader)
npm test             # 60+ unit + integration tests (node:test, zero extra deps)
npm run smoke        # live smoke test against a running DSH (default 127.0.0.1:3080)
```

The test suite covers the CIDR matcher, scrypt hashing, session persistence,
rate limiting, request policy, X.509 generation (validated by a full TLS
handshake), the complete gateway pipeline (proxy, auth, CSRF, lockout,
WebSocket tunnel, TLS), and the Cordis plugin contract (Service lifecycle,
fail-closed validation, loader composition).

## License

MIT
