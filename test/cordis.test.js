// cordis.test.js — DSH plugin-contract integration tests.
//
// These tests mount dsh-full-lan-access exactly the way a DSH deployment
// does: as a Cordis Service class through `ctx.plugin`, and as a loader
// entry through @deepseek-ai/cordis-plugin-loader (the same composition
// mechanism cordis.yml rows use).

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { Context, Service } from '@deepseek-ai/cordis'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import http from 'node:http'
import LanAccess from '../lib/index.js'
import { hashPassword } from '../lib/scrypt.js'
import { ensureSelfLink, PROJECT_ROOT } from './helpers.mjs'

const PASSWORD = 'cordis-test-password'
const HASH = hashPassword(PASSWORD)

function validConfig(overrides = {}) {
  return {
    enabled: true,
    listen: { host: '127.0.0.1', port: 0 },
    upstream: { host: '127.0.0.1', port: 9 }, // replaced per-test
    security: { passwordHash: HASH },
    stateDir: mkdtempSync(join(tmpdir(), 'cordis-lan-')),
    ...overrides,
  }
}

function startFakeUpstream() {
  return new Promise((resolve) => {
    const server = http.createServer((req, res) => {
      res.writeHead(200, { 'content-type': 'text/plain' })
      res.end('cordis-upstream-ok')
    })
    server.listen(0, '127.0.0.1', () => resolve({ server, port: server.address().port }))
  })
}

function get(port, path = '/') {
  return new Promise((resolve, reject) => {
    http.get({ host: '127.0.0.1', port, path }, (res) => {
      let data = ''
      res.on('data', (c) => { data += c })
      res.on('end', () => resolve({ status: res.statusCode, body: data }))
    }).on('error', reject)
  })
}

test('plugin mounts as a Cordis Service and proxies through the gateway', async () => {
  const upstream = await startFakeUpstream()
  const config = validConfig({ upstream: { host: '127.0.0.1', port: upstream.port } })
  const ctx = new Context()
  try {
    await ctx.plugin(LanAccess, config)
    const service = ctx.get('lanAccess')
    assert.ok(service, 'lanAccess service must be registered')
    assert.equal(typeof service.status, 'function')
    assert.equal(typeof service.revokeSession, 'function')

    const status = service.status()
    assert.equal(status.enabled, true)
    assert.equal(status.upstream.port, upstream.port)

    // The gateway must actually serve through the full Cordis lifecycle.
    const port = status.listen.port
    const res = await get(port)
    assert.equal(res.status, 200)
    assert.equal(res.body, 'cordis-upstream-ok')

    const sessions = service.sessions()
    assert.equal(sessions.length, 0)
    assert.equal(service.revokeSession('nope'), false)
  } finally {
    await ctx.fiber.dispose()
    upstream.server.close()
    rmSync(config.stateDir, { recursive: true, force: true })
  }
})

test('fail closed: requireAuth without a password hash rejects startup', async () => {
  const ctx = new Context()
  try {
    await assert.rejects(
      async () => {
        await ctx.plugin(LanAccess, validConfig({ security: { requireAuth: true, passwordHash: null } }))
      },
      /passwordHash is not set/,
    )
  } finally {
    await ctx.fiber.dispose()
  }
})

test('fail closed: a malformed password hash rejects startup', async () => {
  const ctx = new Context()
  try {
    await assert.rejects(
      async () => {
        await ctx.plugin(LanAccess, validConfig({ security: { passwordHash: 'not-a-real-hash' } }))
      },
      /malformed/,
    )
  } finally {
    await ctx.fiber.dispose()
  }
})

test('disabled plugin starts without binding and reports disabled status', async () => {
  const ctx = new Context()
  try {
    await ctx.plugin(LanAccess, validConfig({ enabled: false }))
    const service = ctx.get('lanAccess')
    assert.equal(service.status().enabled, false)
    assert.equal(service.status().listen, null)
  } finally {
    await ctx.fiber.dispose()
  }
})

test('registers a local status route on the DSH webServer when present', async () => {
  /** Minimal fake of the DSH webServer route registry. */
  class FakeWebServer extends Service {
    routes = []
    constructor(ctx) {
      super(ctx, 'webServer')
    }
    register(route) {
      this.routes.push(route)
      return () => {
        const at = this.routes.indexOf(route)
        if (at !== -1) this.routes.splice(at, 1)
      }
    }
  }

  const ctx = new Context()
  try {
    await ctx.plugin(FakeWebServer)
    await ctx.plugin(LanAccess, validConfig())
    const fake = ctx.get('webServer')
    const route = fake.routes.find((r) => r.path === '/__lan_gate/status')
    assert.ok(route, 'status route must be registered on the webServer')
    assert.equal(route.kind, 'exact')

    // The handler serves the JSON status.
    const res = {
      headersSent: false,
      writeHead() {},
      end(body) {
        this.body = body
      },
      destroy() {},
    }
    await route.handler({ method: 'GET' }, res)
    const parsed = JSON.parse(res.body)
    assert.equal(parsed.enabled, true)
  } finally {
    await ctx.fiber.dispose()
  }
})

test('loads as a loader entry (cordis.yml composition mechanism)', async () => {
  ensureSelfLink()
  const upstream = await startFakeUpstream()
  const { default: Loader } = await import('@deepseek-ai/cordis-plugin-loader')
  const baseUrl = PROJECT_ROOT

  const ctx = new Context()
  let entryId
  try {
    await ctx.plugin(Loader, { baseUrl })
    entryId = await ctx.loader.create({
      name: 'dsh-full-lan-access',
      config: validConfig({ upstream: { host: '127.0.0.1', port: upstream.port } }),
    })
    await ctx.loader.await()

    const service = ctx.get('lanAccess')
    assert.ok(service, 'loader entry must expose the lanAccess service')
    const res = await get(service.status().listen.port)
    assert.equal(res.status, 200)
    assert.equal(res.body, 'cordis-upstream-ok')
  } finally {
    if (entryId !== undefined) await ctx.loader.remove(entryId)
    await ctx.fiber.dispose()
    upstream.server.close()
  }
})

test('loader entry with invalid config fails loudly', async () => {
  ensureSelfLink()
  const { default: Loader } = await import('@deepseek-ai/cordis-plugin-loader')
  const baseUrl = PROJECT_ROOT

  const ctx = new Context()
  let entryId
  try {
    await ctx.plugin(Loader, { baseUrl })
    await assert.rejects(
      ctx.loader.create({
        name: 'dsh-full-lan-access',
        config: validConfig({ security: { requireAuth: true, passwordHash: null } }),
      }),
      /passwordHash is not set/,
    )
  } finally {
    if (entryId !== undefined) await ctx.loader.remove(entryId)
    await ctx.fiber.dispose()
  }
})
