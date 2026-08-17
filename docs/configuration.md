# Configuration

The plugin is configured through its row in `cordis.patch.yml`. Every key has
a default; only the keys you set are validated against the Config schema
(schemastery). Unknown keys are rejected by the schema.

## Row shape

```yaml
- id: lan-access
  name: 'dsh-full-lan-access'
  config:
    # ...options below...
```

## Options

### `enabled` — boolean, default `true`

When `false` the plugin starts, registers the `lanAccess` service and the
local status route, but binds no gateway socket.

### `listen` — object

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `host` | string | `'0.0.0.0'` | Interface to bind. `0.0.0.0` exposes all IPv4 interfaces; use a specific LAN IP to restrict. |
| `port` | natural | `3081` | Gateway port. `0` lets the OS pick an ephemeral port (status reports it). |

### `upstream` — object

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `protocol` | `'http' \| 'https'` | `'http'` | Scheme of the DSH web server. |
| `host` | string | `'127.0.0.1'` | DSH bind address. |
| `port` | natural | `3080` | DSH bind port. |

### `security` — object

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `allowCidrs` | string[] | RFC1918 + loopback + IPv6 ULA/link-local (see below) | Addresses permitted through the gateway. |
| `denyCidrs` | string[] | `[]` | Addresses always rejected, even if also in `allowCidrs` (deny wins). |
| `requireAuth` | boolean | `true` | Master switch for password authentication. |
| `passwordHash` | string \| null | `null` | `scrypt$N$r$p$salt$hash` string from `dsh-lan-gate hash-password`. Required when `requireAuth` is true — startup fails otherwise. |
| `loopbackBypassAuth` | boolean | `true` | Loopback clients (`127.0.0.0/8`, `::1`) skip authentication. |
| `rejectProxyHeaders` | boolean | `true` | Reject requests carrying `X-Forwarded-*`, `Forwarded`, `X-Real-IP`, `Via`, … with `400`. The gateway never consults these headers regardless. |

Default `allowCidrs`:

```yaml
allowCidrs:
  - '127.0.0.0/8'
  - '::1/128'
  - '10.0.0.0/8'
  - '172.16.0.0/12'
  - '192.168.0.0/16'
  - 'fc00::/7'
  - 'fe80::/10'
```

### `session` — object

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `ttlSec` | natural | `604800` (7 days) | Session lifetime. |
| `maxSessions` | natural | `64` | Maximum concurrent sessions; the oldest is evicted beyond this. |
| `cookieName` | string | `'dsh_lan_session'` | Session cookie name (the CSRF cookie appends `_csrf`). |

Sessions are stored as SHA-256 token digests in `<stateDir>/sessions.json`
and survive gateway restarts.

### `login` — object

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `maxAttempts` | natural | `5` | Failed attempts allowed per IP within the window. |
| `windowSec` | natural | `900` | Sliding window for attempts. |
| `lockoutSec` | natural | `900` | How long the login page shows the lockout message. |

### `rateLimit` — object

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `enabled` | boolean | `true` | Per-IP throttle for **unauthenticated** non-loopback requests (guards the auth gate and the upstream from anonymous floods). |
| `maxRequests` | natural | `120` | Requests per IP per window. |
| `windowSec` | natural | `60` | Throttle window. |

Authenticated sessions and loopback traffic are never throttled — the DSH
web UI legitimately fires dozens of requests per page load, and an
authorized LAN client must not be punished for it.

### `tls` — object

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `enabled` | boolean | `false` | Serve HTTPS instead of HTTP. |
| `certPath` | string \| null | `null` | PEM certificate file. Must be set together with `keyPath`. |
| `keyPath` | string \| null | `null` | PEM private key file. |
| `selfSignedDays` | natural | `825` | Validity of the auto-generated self-signed certificate. |

When `enabled` and no `certPath`/`keyPath` are set, the gateway generates an
ECDSA P-256 self-signed certificate (SAN: `localhost`, `127.0.0.1`, `::1`,
plus every non-internal interface address) and persists it at
`<stateDir>/tls/server.crt` and `server.key`. The session cookie gets the
`Secure` attribute automatically.

### `stateDir` — string \| null, default `$DSH_HOME/lan-access` (or `~/.dsh-lan-access`)

Where sessions, TLS material, and (if configured) audit files live. This
directory should be readable only by the DSH user.

### `audit` — object

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `file` | string \| null | `null` | Append JSON-lines audit events to this file. |
| `level` | `'error' \| 'warn' \| 'info' \| 'debug'` | `'info'` | Verbosity for the DSH logger sink. |

### `proxy` — object

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `timeoutMs` | natural | `30000` | Upstream request timeout; exceeded requests fail with 502. |

## Example (annotated)

```yaml
- id: lan-access
  name: 'dsh-full-lan-access'
  config:
    listen:
      host: '0.0.0.0'
      port: 3081
    upstream:
      protocol: http
      host: '127.0.0.1'
      port: 3080
    security:
      allowCidrs:
        - '192.168.1.0/24'
        - '10.0.0.0/8'
      denyCidrs:
        - '10.0.0.66/32'
      requireAuth: true
      passwordHash: 'scrypt$16384$8$1$...'
      loopbackBypassAuth: true
      rejectProxyHeaders: true
    session:
      ttlSec: 604800
      maxSessions: 64
    login:
      maxAttempts: 5
      windowSec: 900
      lockoutSec: 900
    rateLimit:
      enabled: true
      maxRequests: 120
      windowSec: 60
    tls:
      enabled: false
      certPath: null
      keyPath: null
    stateDir: null
    audit:
      file: null
      level: info
    proxy:
      timeoutMs: 30000
```

Validate a JSON config file with the CLI:

```bash
npx dsh-lan-gate check-config config.json
```
