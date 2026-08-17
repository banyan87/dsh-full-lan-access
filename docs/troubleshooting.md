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

## LAN/VPN clients cannot reach the gateway

The gateway binds `0.0.0.0` and `node.exe` normally already has a Windows
Firewall allow rule (any TCP port) — so start from the gateway's own
diagnostics:

```bash
curl -s http://127.0.0.1:3081/__lan_gate/status
```

The `urls` field lists every non-internal interface address with the bound
port (the startup log prints the same). If your VPN adapter's address is
there but the remote device still cannot connect:

- **VPN client ACLs** — virtual-LAN products (OrayBox/蒲公英, ZeroTier,
  Tailscale …) often apply their own access control. Check the member /
  device entry for this machine: it must be online and allow inbound
  connections, and the remote device must be a member of the same network.
  Many default to blocking non-HTTP ports or non-whitelisted members.
- **Phone-side proxies** — some mobile browsers/VPN apps proxy only
  `80`/`443`; a non-standard port may not be routed. Try the OrayBox/
  provider hostname, or a direct (non-proxied) browser.
- **Firewall** — verify the listener process is covered:
  `Get-NetFirewallRule -Direction Inbound | ? DisplayName -match node`.
  If not, allow it: `netsh advfirewall firewall add rule name="dsh-lan-access"
  dir=in action=allow protocol=TCP localport=3081` (run as administrator).
- From the remote device: `ping <host-ip>` first, then a port probe.

## The web UI looks stale after an update (language, plugin pages, models)

After restarting DSH with a new gateway version, **hard-refresh** the
browser tab (`Ctrl+F5` / clear the site's cache). The DSH page is cached
per-origin, and an old tab keeps running the previous session's code (the
`crypto.randomUUID` polyfill and Origin rewriting only exist in the freshly
served page). If a tab still misbehaves, close it entirely and reopen
`http://<lan-ip>:3081`.

## Workspace creation opens a folder dialog on the host instead of a web picker

By design (since 1.3.0) the bundle pins the browser-based picker, so
workspace creation uses an in-page directory browser that works from any
device. If you previously overrode the picker rows, or want the native OS
chooser back for the host's own desktop, re-enable it from the profile's
patch layer:

```yaml
- id: directory-picker
  disabled: false
- id: directory-picker-browse
  disabled: true
- id: ui-directory-picker-browse
  disabled: true
```

## Where are the logs?

- DSH logger: the gateway logs `listening`, `stopping`, and audit lines at
  `info`/`debug`.
- `audit.file` (if configured): JSON lines, one event per line. Tail it:

```bash
tail -f "$DSH_HOME/lan-access/audit.jsonl"
```
