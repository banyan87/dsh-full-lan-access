# Gateway API

The gateway exposes three local endpoints under `/__lan_gate/` plus the
proxied DSH surface. All endpoint responses are `Cache-Control: no-store`.

## `GET /__lan_gate/login`

Renders the login page. Always sets a CSRF cookie
(`dsh_lan_session_csrf`, HttpOnly, SameSite=Lax). When the client is in
lockout, the page shows the remaining wait.

**200** — HTML login form.

## `POST /__lan_gate/login`

`application/x-www-form-urlencoded` body with `password` and `csrf`.

| Outcome | Status | Response |
| --- | --- | --- |
| Rate-limited (too many attempts) | `429` | HTML page with lockout message |
| Missing/mismatched CSRF token | `403` | HTML page with error |
| Wrong password | `401` | HTML page with error |
| Success | `302` | `Location: /` + `Set-Cookie: dsh_lan_session=<token>; Path=/; HttpOnly; SameSite=Lax; Max-Age=<ttl>; [Secure]` |

## `GET /__lan_gate/logout`

Revokes the session and clears the cookie.

**302** — to `/__lan_gate/login`.

## `GET /__lan_gate/status`

In auth mode (non-loopback) this endpoint itself requires a valid session
cookie; on loopback it is open.

**200** — JSON:

```jsonc
{
  "service": "dsh-lan-access",
  "version": "1.0.0",
  "startedAt": "2026-08-17T12:00:00.000Z",
  "uptimeSec": 42,
  "listen": { "host": "0.0.0.0", "port": 3081, "family": "IPv4" },
  "tls": { "enabled": false },
  "sessions": { "count": 1, "max": 64, "ttlSec": 604800 },
  "security": {
    "requireAuth": true,
    "authConfigured": true,
    "loopbackBypassAuth": true,
    "rejectProxyHeaders": true,
    "allowCidrs": ["127.0.0.0/8", "::1/128", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7", "fe80::/10"],
    "denyCidrs": []
  },
  "upstream": { "protocol": "http", "host": "127.0.0.1", "port": 3080 },
  "audit": { "level": "info" }
}
```

The password hash is never included. `authConfigured` reports whether a hash
is present, not the hash.

The same payload (minus the gateway-bound fields) is served on the DSH web
server itself at `http://127.0.0.1:3080/__lan_gate/status` — loopback only,
via the plugin's `webServer` route registration.

## Proxied surface

Everything else (after passing the pipeline) is streamed to the upstream DSH
web server verbatim — the SPA, its assets, `/api/*` RPC, and WebSocket
upgrades.

## Error responses

| Status | Meaning |
| --- | --- |
| `400` | Unresolvable client address, or proxy headers present while `rejectProxyHeaders` is on |
| `401` | Authentication required (API-style requests get JSON `{"error":"unauthorized","login":"/__lan_gate/login"}`) |
| `403` | Address denied by or absent from the CIDR policy |
| `429` | Rate limited (`Retry-After` set) or login locked out |
| `502` | Upstream unreachable or timed out |
| `405` | Wrong method on a gateway-local endpoint |

## Cookies

| Cookie | Attributes | Purpose |
| --- | --- | --- |
| `dsh_lan_session` | `Path=/; HttpOnly; SameSite=Lax; Max-Age=<ttl>` (+ `Secure` under TLS) | Gateway session |
| `dsh_lan_session_csrf` | `Path=/; HttpOnly; SameSite=Lax` (+ `Secure` under TLS) | CSRF double-submit token |

Both cookies are stripped from proxied requests — they never reach DSH.
