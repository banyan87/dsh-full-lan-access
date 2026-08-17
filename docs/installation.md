# Installation

`dsh-full-lan-access` is a host-only Cordis plugin for the DSH `web` profile.
It needs no changes to the DSH web server itself: the DSH server stays bound
to `127.0.0.1` and the plugin's gateway listens on the LAN.

The package is a **profile bundle**: its manifest declares `dsh.bundle.patch`,
so `dsh plugin add` registers it as a composition layer whose `cordis.patch.yml`
inserts the `lan-access` row automatically. You only supply the configuration
(hash, networks, …) from your profile's own patch layer.

## Prerequisites

- DSH `0.1.0-rc.x` (web profile)
- Node.js ≥ 20
- `dsh` CLI on `PATH` (for `dsh plugin`), or direct `pnpm` access to the
  profile directory

## 1. Install the package into the web profile

```bash
dsh plugin --profile web add dsh-full-lan-access
```

This forwards to pnpm inside `$DSH_HOME/profiles/web`, then reconciles the
profile's `dsh.profile.bundles` list — a package that declares `dsh.bundle`
joins the layer stack. If the package is not yet published to npm, install
from a local path or git:

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

## 3. Configure the row from your own patch layer

The bundle already inserted the row (id `lan-access`, package
`dsh-full-lan-access`). Edit `$DSH_HOME/profiles/web/cordis.patch.yml` and
override its config by id — no `name` needed:

```yaml
- id: lan-access
  config:
    security:
      passwordHash: 'scrypt$16384$8$1$...'   # from step 2
```

> **Why a plain row with `- id:` works here:** the profile's patch layer
> targets existing rows by id (per-key merge; `config` replaces wholesale).
> The bundle provided the row; you provide the config. If the row does NOT
> exist (manual installs without the bundle), a bare `- id:` patch is
> skipped with a warning — use the `insert:` form instead (see
> [`examples/cordis.patch.example.yml`](../examples/cordis.patch.example.yml)
> and the manual flow below).

## 4. Restart the web profile

```bash
dsh web           # or however you start your DSH web profile
```

> **First boot without step 3 fails closed — deliberately.** The bundle row
> ships with no config, and the plugin refuses to start unauthenticated. The
> boot log shows:
>
> ```
> dsh-lan-access: security.requireAuth is true but security.passwordHash is
> not set. Generate one with: dsh-lan-gate hash-password
> ```
>
> Complete step 3 and restart. The gateway never starts half-configured.

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

## Manual flow (install without the bundle)

If the package was installed as a plain dependency (its manifest did not
declare `dsh.bundle` at install time), the row is not in the composition. Add
it yourself with an `insert` patch — a bare `- id:` row would target nothing
and be skipped:

```yaml
- insert:
    - id: lan-access
      name: 'dsh-full-lan-access'
      config:
        enabled: true
        security:
          passwordHash: 'scrypt$16384$8$1$...'
```

A fully-annotated insert example lives in
[`examples/cordis.patch.example.yml`](../examples/cordis.patch.example.yml).

## Updating

```bash
dsh plugin --profile web update dsh-full-lan-access
```

The `dsh plugin` reconcile step re-checks the installed manifest, so a
package that gains a `dsh.bundle` declaration in a newer version joins the
layer stack automatically.

## Removing

```bash
dsh plugin --profile web remove dsh-full-lan-access
# and delete the `lan-access` override from cordis.patch.yml
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
