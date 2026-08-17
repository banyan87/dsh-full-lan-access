# Troubleshooting

## The plugin row fails to load

The loader reports a row failure with a message from the plugin. Common
causes:

| Message | Fix |
| --- | --- |
| `security.requireAuth is true but security.passwordHash is not set` | Run `npx dsh-lan-gate hash-password` and put the hash in the row config. This is the fail-closed default. |
| `security.passwordHash is malformed` | The hash must match `scrypt$N$r$p$salt$hash`. Re-generate with the CLI. |
| `invalid CIDR "..."` | Check `allowCidrs`/`denyCidrs` for typos (`192.168.1.0/24` not `192.168.1.0-24`). |
| `listen.port must be an integer in 0..65535` | The port must be a number, not a string (YAML quoting pitfall: `port: '3081'`). |

## Port already in use

The gateway defaults to `3081`. If another service holds it, either change
`listen.port` or check for a stray gateway process:

```bash
netstat -ano | findstr :3081     # Windows
ss -tlnp | grep 3081             # Linux
```

## LAN clients get 403

- The client's real address is not in `allowCidrs`. Find it from the audit
  log (`ip-not-allowed` events) or `ipconfig`/`ip addr` on the client.
- Remember: `denyCidrs` wins over `allowCidrs`.
- The gateway resolves addresses only from the socket — a client behind a
  router without NAT loopback may appear as the router's LAN IP. That is
  expected; allow the router's LAN address if you want those clients in.

## LAN clients get 400

`rejectProxyHeaders` is on and the client sent `X-Forwarded-For` (or similar).
Some clients/browsers add these automatically via proxy settings. Either fix
the client, or — only if you fully understand the tradeoff — set
`rejectProxyHeaders: false` (the gateway still never *uses* those headers).

## Login keeps failing

- The password is verified against `passwordHash` in the **row config** —
  re-hashing with the CLI produces a *different* hash each time (random
  salt); make sure the row config actually contains the hash you verified:
  `npx dsh-lan-gate verify <password> <hash>`.
- After `maxAttempts` failures the IP is locked out for `lockoutSec`.
- Check the audit log (`auth-failed`, `auth-locked`, `csrf-rejected`).

## The DSH web UI works on 127.0.0.1:3080 but not through the gateway

- Verify the upstream: `curl http://127.0.0.1:3080/` on the host.
- Verify the gateway status: `curl http://127.0.0.1:3081/__lan_gate/status`.
- Check `upstream.host`/`upstream.port` — they must point at the DSH web
  server's bind address (default `127.0.0.1:3080`).
- DSH itself must be running; the gateway logs `proxy-error` (502) when the
  upstream is unreachable.

## WebSocket connections fail after login

- WebSocket upgrades carry their own cookies — ensure the client sends the
  session cookie on the upgrade request (browsers do automatically).
- Non-browser clients must replicate the login flow and then send the cookie
  on the upgrade handshake.
- The audit log records `auth-required ... kind: websocket` for rejected
  upgrades.

## Sessions disappear after restart

Sessions live in `<stateDir>/sessions.json` (digests + expiry). If the state
directory was deleted or moved, all sessions are invalid — users simply log
in again. This is by design (fail closed).

## Self-signed certificate warnings in browsers

`tls.enabled` with no `certPath`/`keyPath` generates a self-signed cert
stored at `<stateDir>/tls/`. Install it in the client's trust store, or
provide your own certificate via `tls.certPath`/`tls.keyPath`.

## TLS enabled but the browser says "connection refused"

Ensure `tls.enabled: true` **and** that clients use `https://`, not `http://`.
The gateway serves one protocol per listener.

## Where are the logs?

- DSH logger: the gateway logs `listening`, `stopping`, and audit lines at
  `info`/`debug`.
- `audit.file` (if configured): JSON lines, one event per line. Tail it:

```bash
tail -f "$DSH_HOME/lan-access/audit.jsonl"
```
