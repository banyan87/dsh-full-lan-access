// index.js — the dsh-full-lan-access Cordis plugin entry.
//
// A host-only plugin: starts the secure LAN gateway (its own listener on
// 0.0.0.0) that reverse-proxies to the DSH web server running on loopback.
// The plugin also exposes:
//   - the `lanAccess` Cordis service (status / sessions / revokeSession)
//   - a local `/__lan_gate/status` route on the DSH web server when present
//
// Install by adding a row to the profile's cordis.patch.yml, e.g.:
//
//   - id: lan-access
//     name: 'dsh-full-lan-access'
//     config:
//       security:
//         passwordHash: 'scrypt$16384$8$1$...'

import { Service } from '@deepseek-ai/cordis'
import z from '@deepseek-ai/schemastery'
import { createGateway } from './server.js'
import { resolveConfig } from './config.js'
import { sendJson } from './httpkit.js'

export const Config = z.object({
  enabled: z.boolean().default(true),
  listen: z.object({
    host: z.string().default('0.0.0.0'),
    port: z.natural().default(3081),
  }),
  upstream: z.object({
    protocol: z.union([z.const('http'), z.const('https')]).default('http'),
    host: z.string().default('127.0.0.1'),
    port: z.natural().default(3080),
  }),
  security: z.object({
    allowCidrs: z.array(z.string()).default([
      '127.0.0.0/8',
      '::1/128',
      '10.0.0.0/8',
      '172.16.0.0/12',
      '192.168.0.0/16',
      'fc00::/7',
      'fe80::/10',
    ]),
    denyCidrs: z.array(z.string()).default([]),
    requireAuth: z.boolean().default(true),
    passwordHash: z.union([z.string(), z.const(null)]).default(null),
    loopbackBypassAuth: z.boolean().default(true),
    rejectProxyHeaders: z.boolean().default(true),
  }),
  session: z.object({
    ttlSec: z.natural().default(7 * 24 * 60 * 60),
    maxSessions: z.natural().default(64),
    cookieName: z.string().default('dsh_lan_session'),
  }),
  login: z.object({
    maxAttempts: z.natural().default(5),
    windowSec: z.natural().default(15 * 60),
    lockoutSec: z.natural().default(15 * 60),
  }),
  rateLimit: z.object({
    enabled: z.boolean().default(true),
    maxRequests: z.natural().default(120),
    windowSec: z.natural().default(60),
  }),
  tls: z.object({
    enabled: z.boolean().default(false),
    certPath: z.union([z.string(), z.const(null)]).default(null),
    keyPath: z.union([z.string(), z.const(null)]).default(null),
    selfSignedDays: z.natural().default(825),
  }),
  stateDir: z.union([z.string(), z.const(null)]).default(null),
  audit: z.object({
    file: z.union([z.string(), z.const(null)]).default(null),
    level: z.string().default('info'),
  }),
  proxy: z.object({
    timeoutMs: z.natural().default(30_000),
  }),
})

/**
 * The `lanAccess` service: owns the gateway lifecycle and exposes an
 * operations surface for other plugins and tools.
 */
export class LanAccess extends Service {
  static Config = Config

  constructor(ctx, config) {
    super(ctx, 'lanAccess')
    this.resolved = resolveConfig(config)
    this.gateway = createGateway(this.resolved, { logger: ctx.logger })

    // Own the gateway's whole lifetime; stopping or updating the plugin
    // closes the listener, sockets, sessions, and audit log.
    ctx.effect(() => () => {
      void this.gateway.close()
    })

    // Local status route on the DSH web server (loopback only, no auth).
    const webServer = ctx.get('webServer')
    if (webServer !== undefined) {
      ctx.effect(() => webServer.register({
        kind: 'exact',
        path: '/__lan_gate/status',
        handler: async (req, res) => {
          sendJson(res, 200, {
            ...this.status(),
            enabled: this.resolved.enabled,
            configured: this.resolved.enabled,
          })
        },
      }))
    }
  }

  /** Start listening; rejects the fiber on bind failure (fail closed). */
  async [Service.init]() {
    if (this.resolved.enabled) {
      await this.gateway.listen()
    }
  }

  /** Sanitized runtime status. */
  status() {
    return this.gateway.status()
  }

  /** List live gateway sessions (id + expiry). */
  sessions() {
    return this.gateway.sessions()
  }

  /** Revoke one session by token. */
  revokeSession(token) {
    return this.gateway.revokeSession(token)
  }

  /** Revoke one session by id. */
  revokeSessionById(id) {
    return this.gateway.revokeSessionById(id)
  }
}

export default LanAccess
