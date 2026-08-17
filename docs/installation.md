# Installation

`dsh-full-lan-access` is a host-only Cordis plugin for the DSH `web` profile.
It needs no changes to the DSH web server itself: the DSH server stays bound
to `127.0.0.1` and the plugin's gateway listens on the LAN.

## Prerequisites

- DSH `0.1.0-rc.x` (web profile)
- Node.js ≥ 20
- `dsh` CLI on `PATH` (for `dsh plugin`), or direct `pnpm` access to the
  profile directory

## 1. Install the package into the web profile

```bash
dsh plugin --profile web add dsh-full-lan-access
```

This forwards to pnpm inside `$DSH_HOME/profiles/web`. If the package is not
yet published to npm, install from a local path or git:

```bash
dsh plugin --profile web add "file:../dsh-full-lan-access"
# or
dsh plugin --profile web add "github:your-user/dsh-full-lan-access"
```

## 2. Generate a password hash

```bash
npx dsh-lan-gate hash-password        # interactive (no echo)
# or pass it as an argument:
npx dsh-lan-gate hash-password "my-secret-password"
```

Copy the printed `scrypt$16384$8$1$...` string. Treat it like a password —
anyone with the hash (and write access to your profile config) can verify
passwords against it.

## 3. Add the plugin row

Edit `$DSH_HOME/profiles/web/cordis.patch.yml` and add:

```yaml
- id: lan-access
  name: 'dsh-full-lan-access'
  config:
    security:
      passwordHash: 'scrypt$16384$8$1$...'   # from step 2
```

A fully-annotated example lives in
[`examples/cordis.patch.example.yml`](../examples/cordis.patch.example.yml).

> **Fail closed:** with `security.requireAuth: true` (the default) the plugin
> refuses to start when `passwordHash` is missing or malformed — DSH will
> report the row as failed with a clear message. This is deliberate.

## 4. Restart the web profile

```bash
dsh web           # or however you start your DSH web profile
```

Watch the startup log for:

```
[lan-access] listening on 0.0.0.0:3081 → upstream http://127.0.0.1:3080
```

## 5. Verify

From the DSH host:

```bash
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:3081/        # 200 (loopback bypass)
curl -s http://127.0.0.1:3081/__lan_gate/status                        # JSON status
```

From another device on the LAN:

```bash
curl -s -o /dev/null -w '%{http_code}\n' http://<your-lan-ip>:3081/    # 302 → login
```

Open `http://<your-lan-ip>:3081` in a browser, sign in with the password from
step 2, and you should land on the DSH web UI.

## Updating

```bash
dsh plugin --profile web update dsh-full-lan-access
```

## Removing

```bash
dsh plugin --profile web remove dsh-full-lan-access
# and delete the `lan-access` row from cordis.patch.yml
```

## Running without a DSH profile (standalone)

The gateway core (`lib/server.js`) is independent of Cordis and can be run
directly:

```bash
node -e "import('./lib/server.js').then(async ({ createGateway }) => {
  const { resolveConfig } = await import('./lib/config.js')
  const g = createGateway(resolveConfig({ security: { passwordHash: 'scrypt$...' } }), { logger: console })
  await g.listen()
})"
```

Useful for testing against any upstream HTTP service, not just DSH.
