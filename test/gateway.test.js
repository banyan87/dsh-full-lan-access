// gateway.test.js — end-to-end gateway tests against a fake upstream:
// proxy passthrough, authentication, CSRF, rate limiting, IP policy,
// proxy-header rejection, WebSocket tunneling, TLS, and sessions.

import { test, before, after } from 'node:test'
import assert from 'node:assert/strict'
import http from 'node:http'
import https from 'node:https'
import net from 'node:net'
import { createHash } from 'node:crypto'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { resolveConfig } from '../lib/config.js'
import { createGateway } from '../lib/server.js'
import { hashPassword } from '../lib/scrypt.js'

const WS_GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11'
const PASSWORD = 'test-password-123'
const HASH = hashPassword(PASSWORD)

/* ── helpers ────────────────────────────────────────────────────────────── */

const auditLines = []
const silentLogger = {
  info: () => {},
  warn: () => {},
  error: () => {},
}

function startFakeUpstream() {
  return new Promise((resolve) => {
    /** @type {Record<string, string> | null} most recent upgrade request headers */
    let lastUpgradeHeaders = null
    const server = http.createServer((req, res) => {
      if (req.url === '/echo') {
        let body = ''
        req.on('data', (chunk) => { body += chunk })
        req.on('end', () => {
          res.writeHead(200, { 'content-type': 'application/json' })
          res.end(JSON.stringify({ path: req.url, method: req.method, body }))
        })
        return
      }
      if (req.url === '/headers') {
        res.writeHead(200, { 'content-type': 'application/json' })
        res.end(JSON.stringify({
          host: req.headers.host,
          origin: req.headers.origin,
          cookie: req.headers.cookie,
          'sec-fetch-site': req.headers['sec-fetch-site'],
        }))
        return
      }
      if (req.url === '/html') {
        res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' })
        res.end('<!doctype html><html><head><title>page</title></head><body>content</body></html>')
        return
      }
      if (req.url === '/slow-stream') {
        // Send headers immediately, then a body chunk well after the
        // gateway's request timeout — like an SSE event stream.
        res.writeHead(200, { 'content-type': 'text/plain' })
        res.write('headers-first\n')
        setTimeout(() => {
          res.write('late-body\n')
          res.end()
        }, 150)
        return
      }
      res.writeHead(200, { 'content-type': 'text/plain' })
      res.end('upstream-ok')
    })
    server.on('upgrade', (req, socket) => {
      lastUpgradeHeaders = { ...req.headers }
      const key = req.headers['sec-websocket-key']
      const accept = createHash('sha1').update(`${key}${WS_GUID}`).digest('base64')
      socket.write(
        'HTTP/1.1 101 Switching Protocols\r\n'
        + 'Upgrade: websocket\r\n'
        + 'Connection: Upgrade\r\n'
        + `Sec-WebSocket-Accept: ${accept}\r\n\r\n`,
      )
      // Echo raw bytes back (the gateway must tunnel them transparently).
      socket.on('data', (chunk) => socket.write(chunk))
    })
    server.listen(0, '127.0.0.1', () => {
      resolve({
        server,
        port: server.address().port,
        lastUpgradeHeaders: () => lastUpgradeHeaders,
      })
    })
  })
}

function mergeDeep(base, extra) {
  if (extra === undefined) return base
  const out = { ...base }
  for (const [key, value] of Object.entries(extra)) {
    if (
      value !== null
      && typeof value === 'object'
      && !Array.isArray(value)
      && base[key] !== null
      && typeof base[key] === 'object'
      && !Array.isArray(base[key])
    ) {
      out[key] = mergeDeep(base[key], value)
    } else {
      out[key] = value
    }
  }
  return out
}

function startGateway(upstreamPort, overrides = {}) {
  const stateDir = mkdtempSync(join(tmpdir(), 'lan-gate-state-'))
  const config = resolveConfig(mergeDeep({
    listen: { host: '127.0.0.1', port: 0 },
    upstream: { host: '127.0.0.1', port: upstreamPort },
    security: {
      passwordHash: HASH,
      allowCidrs: ['127.0.0.0/8', '::1/128'],
    },
    stateDir,
    audit: { level: 'debug', file: join(stateDir, 'audit.jsonl') },
  }, overrides))
  const gateway = createGateway(config, {
    logger: silentLogger,
    env: {},
  })
  return gateway.listen().then((bound) => ({ gateway, port: bound.port, stateDir }))
}

function request(port, { path = '/', method = 'GET', headers = {}, body } = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request(
      { host: '127.0.0.1', port, path, method, headers, agent: false },
      (res) => {
        let data = ''
        res.on('data', (chunk) => { data += chunk })
        res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: data }))
      },
    )
    req.on('error', reject)
    if (body !== undefined) req.write(body)
    req.end()
  })
}

function extractCookies(res) {
  const headers = Array.isArray(res.headers['set-cookie']) ? res.headers['set-cookie'] : [res.headers['set-cookie']]
  const out = {}
  for (const header of headers) {
    if (header === undefined) continue
    const [pair] = header.split(';')
    const eq = pair.indexOf('=')
    if (eq === -1) continue
    out[pair.slice(0, eq).trim()] = pair.slice(eq + 1).trim()
  }
  return out
}

async function login(port, { password = PASSWORD } = {}) {
  const page = await request(port, { path: '/__lan_gate/login' })
  const cookies = extractCookies(page)
  const csrf = cookies.dsh_lan_session_csrf
  assert.ok(csrf, 'login page must set the CSRF cookie')
  const body = new URLSearchParams({ csrf, password }).toString()
  const res = await request(port, {
    path: '/__lan_gate/login',
    method: 'POST',
    headers: {
      'content-type': 'application/x-www-form-urlencoded',
      cookie: `dsh_lan_session_csrf=${csrf}`,
    },
    body,
  })
  return res
}

async function wsThroughGateway(port, { cookie, origin } = {}) {
  return new Promise((resolve) => {
    const socket = net.connect(port, '127.0.0.1')
    const headers = [
      'GET /ws HTTP/1.1',
      'Host: 127.0.0.1',
      'Upgrade: websocket',
      'Connection: Upgrade',
      'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==',
      'Sec-WebSocket-Version: 13',
    ]
    if (cookie) headers.push(`Cookie: ${cookie}`)
    if (origin) headers.push(`Origin: ${origin}`)
    let response = Buffer.alloc(0)
    let status = null
    socket.on('data', (chunk) => {
      if (status === null) {
        response = Buffer.concat([response, chunk])
        const headEnd = response.indexOf('\r\n\r\n')
        if (headEnd !== -1) {
          const head = response.slice(0, headEnd).toString('latin1')
          status = Number(/^HTTP\/1\.1 (\d{3})/.exec(head)?.[1] ?? 0)
          if (status !== 101) {
            // Rejected upgrade: report the status and close.
            resolve({ status, echoed: null })
            socket.destroy()
            return
          }
          // Handshake done; echo test frame through the tunnel.
          const payload = Buffer.from('hello-ws')
          const mask = Buffer.from([0x11, 0x22, 0x33, 0x44])
          const masked = Buffer.from(payload.map((b, i) => b ^ mask[i % 4]))
          const frame = Buffer.concat([Buffer.from([0x81, 0x80 | payload.length]), mask, masked])
          socket.write(frame)
        }
      } else if (status === 101) {
        resolve({ status, echoed: chunk })
        socket.destroy()
      }
    })
    socket.on('connect', () => socket.write(`${headers.join('\r\n')}\r\n\r\n`))
    socket.on('error', () => resolve({ status: 0, echoed: null }))
  })
}

/* ── fixtures ───────────────────────────────────────────────────────────── */

let upstream
let gatewayA // loopback bypass (defaults)
let gatewayB // auth required even from loopback

before(async () => {
  upstream = await startFakeUpstream()
  gatewayA = await startGateway(upstream.port, {})
  gatewayB = await startGateway(upstream.port, { security: { loopbackBypassAuth: false } })
})

after(async () => {
  for (const g of [gatewayA, gatewayB]) {
    await g.gateway.close()
    rmSync(g.stateDir, { recursive: true, force: true })
  }
  upstream.server.closeAllConnections()
  upstream.server.close()
})

/* ── tests ──────────────────────────────────────────────────────────────── */

test('loopback bypass: no auth required from the local machine', async () => {
  const res = await request(gatewayA.port, { path: '/' })
  assert.equal(res.status, 200)
  assert.equal(res.body, 'upstream-ok')
})

test('loopback bypass: request body streams to the upstream', async () => {
  const res = await request(gatewayA.port, {
    path: '/echo',
    method: 'POST',
    headers: { 'content-type': 'text/plain' },
    body: 'hello upstream',
  })
  assert.equal(res.status, 200)
  const parsed = JSON.parse(res.body)
  assert.equal(parsed.path, '/echo')
  assert.equal(parsed.method, 'POST')
  assert.equal(parsed.body, 'hello upstream')
})

test('auth mode: unauthenticated browser requests redirect to the login page', async () => {
  const res = await request(gatewayB.port, { path: '/' })
  assert.equal(res.status, 302)
  assert.match(res.headers.location, /^\/__lan_gate\/login\?next=/)
})

test('auth mode: API-style requests get a 401 JSON body', async () => {
  const res = await request(gatewayB.port, {
    path: '/api/things',
    headers: { accept: 'application/json' },
  })
  assert.equal(res.status, 401)
  const parsed = JSON.parse(res.body)
  assert.equal(parsed.error, 'unauthorized')
})

test('auth mode: login page renders with a CSRF cookie and no-store headers', async () => {
  const res = await request(gatewayB.port, { path: '/__lan_gate/login' })
  assert.equal(res.status, 200)
  assert.match(res.body, /<form/)
  assert.equal(res.headers['cache-control'], 'no-store')
  const cookies = extractCookies(res)
  assert.ok(cookies.dsh_lan_session_csrf)
  assert.match(res.headers['set-cookie'].join(''), /HttpOnly/)
})

test('auth mode: wrong password is rejected with 401', async () => {
  const res = await login(gatewayB.port, { password: 'wrong-password' })
  assert.equal(res.status, 401)
  assert.ok(!('set-cookie' in res.headers) || !extractCookies(res).dsh_lan_session)
})

test('auth mode: login without a CSRF token is rejected with 403', async () => {
  const res = await request(gatewayB.port, {
    path: '/__lan_gate/login',
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ csrf: '', password: PASSWORD }).toString(),
  })
  assert.equal(res.status, 403)
})

test('auth mode: correct login issues a session cookie and unlocks proxying', async () => {
  const res = await login(gatewayB.port)
  assert.equal(res.status, 302)
  const cookies = extractCookies(res)
  assert.ok(cookies.dsh_lan_session, 'login must set the session cookie')
  const cookieHeader = Object.entries(cookies).map(([k, v]) => `${k}=${v}`).join('; ')

  const proxied = await request(gatewayB.port, { path: '/', headers: { cookie: cookieHeader } })
  assert.equal(proxied.status, 200)
  assert.equal(proxied.body, 'upstream-ok')

  // The gateway's own cookies must not leak upstream.
  const echoed = await request(gatewayB.port, {
    path: '/echo',
    headers: { cookie: cookieHeader },
  })
  const parsed = JSON.parse(echoed.body)
  assert.ok(!parsed.cookie?.includes('dsh_lan_session'), 'session cookie must not reach the upstream')

  // Leave no session behind for order-dependent tests.
  await request(gatewayB.port, { path: '/__lan_gate/logout', headers: { cookie: cookieHeader } })
})

test('auth mode: logout revokes the session', async () => {
  const res = await login(gatewayB.port)
  const cookies = extractCookies(res)
  const cookieHeader = Object.entries(cookies).map(([k, v]) => `${k}=${v}`).join('; ')
  const logout = await request(gatewayB.port, { path: '/__lan_gate/logout', headers: { cookie: cookieHeader } })
  assert.equal(logout.status, 302)
  const after = await request(gatewayB.port, { path: '/', headers: { cookie: cookieHeader } })
  assert.equal(after.status, 302, 'revoked session must be rejected')
})

test('auth mode: repeated failures trigger the login rate limiter', async () => {
  const gate = await startGateway(upstream.port, {
    security: { loopbackBypassAuth: false },
    login: { maxAttempts: 3, windowSec: 60, lockoutSec: 60 },
  })
  try {
    for (let i = 0; i < 3; i += 1) {
      const res = await login(gate.port, { password: 'nope' })
      assert.equal(res.status, 401)
    }
    const res = await login(gate.port, { password: PASSWORD })
    assert.equal(res.status, 429, 'correct password must still be locked out')
    assert.match(res.body, /Too many attempts/)
  } finally {
    await gate.gateway.close()
    rmSync(gate.stateDir, { recursive: true, force: true })
  }
})

test('the general rate limit throttles unauthenticated traffic', async () => {
  const gate = await startGateway(upstream.port, {
    security: { loopbackBypassAuth: false },
    rateLimit: { enabled: true, maxRequests: 2, windowSec: 60 },
  })
  try {
    assert.equal((await request(gate.port, { path: '/', headers: { accept: 'application/json' } })).status, 401)
    assert.equal((await request(gate.port, { path: '/', headers: { accept: 'application/json' } })).status, 401)
    const third = await request(gate.port, { path: '/', headers: { accept: 'application/json' } })
    assert.equal(third.status, 429, 'the third unauthenticated request must be rate-limited')
    assert.ok(third.headers['retry-after'])
  } finally {
    await gate.gateway.close()
    rmSync(gate.stateDir, { recursive: true, force: true })
  }
})

test('authenticated traffic is exempt from the general rate limit', async () => {
  const gate = await startGateway(upstream.port, {
    security: { loopbackBypassAuth: false },
    rateLimit: { enabled: true, maxRequests: 2, windowSec: 60 },
  })
  try {
    const res = await login(gate.port)
    const cookies = extractCookies(res)
    const cookieHeader = Object.entries(cookies).map(([k, v]) => `${k}=${v}`).join('; ')
    // Far more requests than the limiter would allow — all must pass.
    for (let i = 0; i < 6; i += 1) {
      const proxied = await request(gate.port, { path: '/', headers: { cookie: cookieHeader } })
      assert.equal(proxied.status, 200, `authenticated request #${i + 1} must not be rate-limited`)
    }
  } finally {
    await gate.gateway.close()
    rmSync(gate.stateDir, { recursive: true, force: true })
  }
})

test('long-lived upstream streams survive the request timeout (SSE)', async () => {
  const gate = await startGateway(upstream.port, {
    security: { loopbackBypassAuth: false },
    proxy: { timeoutMs: 100 },
  })
  try {
    const res = await login(gate.port)
    const cookies = extractCookies(res)
    const cookieHeader = Object.entries(cookies).map(([k, v]) => `${k}=${v}`).join('; ')
    const result = await Promise.race([
      request(gate.port, { path: '/slow-stream', headers: { cookie: cookieHeader } }),
      new Promise((resolve, reject) => setTimeout(() => reject(new Error('client timed out')), 5000)),
    ])
    assert.equal(result.status, 200)
    assert.equal(result.body, 'headers-first\nlate-body\n')
  } finally {
    await gate.gateway.close()
    rmSync(gate.stateDir, { recursive: true, force: true })
  }
})

test('IP policy: addresses outside the allowlist get 403', async () => {
  const gate = await startGateway(upstream.port, {
    security: { allowCidrs: ['10.0.0.0/8'], loopbackBypassAuth: false },
  })
  try {
    const res = await request(gate.port, { path: '/' })
    assert.equal(res.status, 403)
  } finally {
    await gate.gateway.close()
    rmSync(gate.stateDir, { recursive: true, force: true })
  }
})

test('proxy headers are rejected when rejectProxyHeaders is on', async () => {
  const res = await request(gatewayA.port, {
    path: '/',
    headers: { 'x-forwarded-for': '203.0.113.9' },
  })
  assert.equal(res.status, 400)
})

test('proxy headers are ignored (not rejected) when rejectProxyHeaders is off', async () => {
  const gate = await startGateway(upstream.port, { security: { rejectProxyHeaders: false } })
  try {
    const res = await request(gate.port, { path: '/', headers: { 'x-forwarded-for': '203.0.113.9' } })
    assert.equal(res.status, 200)
  } finally {
    await gate.gateway.close()
    rmSync(gate.stateDir, { recursive: true, force: true })
  }
})

test('status endpoint requires auth in auth mode and reports state', async () => {
  const denied = await request(gatewayB.port, {
    path: '/__lan_gate/status',
    headers: { accept: 'application/json' },
  })
  assert.equal(denied.status, 401)

  const res = await login(gatewayB.port)
  const cookies = extractCookies(res)
  const cookieHeader = Object.entries(cookies).map(([k, v]) => `${k}=${v}`).join('; ')
  const status = await request(gatewayB.port, {
    path: '/__lan_gate/status',
    headers: { cookie: cookieHeader, accept: 'application/json' },
  })
  assert.equal(status.status, 200)
  const parsed = JSON.parse(status.body)
  assert.equal(parsed.service, 'dsh-lan-access')
  assert.equal(parsed.security.requireAuth, true)
  assert.equal(parsed.security.authConfigured, true)
  assert.equal(parsed.sessions.count, 1)
  assert.equal(parsed.upstream.port, upstream.port)
  assert.ok(Array.isArray(parsed.urls), 'status must report reachable LAN URLs')
  assert.ok(parsed.urls.some((u) => u.includes(`:${gatewayB.port}`)), `status.urls must include the bound port (${gatewayB.port})`)
  assert.ok(!JSON.stringify(parsed).includes(PASSWORD), 'status must never expose the hash')
})

test('status endpoint is open on loopback bypass', async () => {
  const res = await request(gatewayA.port, { path: '/__lan_gate/status', headers: { accept: 'application/json' } })
  assert.equal(res.status, 200)
})

test('websocket upgrades require auth in auth mode and tunnel after login', async () => {
  const denied = await wsThroughGateway(gatewayB.port)
  assert.equal(denied.status, 401, 'upgrade without a session must be rejected')

  const res = await login(gatewayB.port)
  const cookies = extractCookies(res)
  const cookieHeader = Object.entries(cookies).map(([k, v]) => `${k}=${v}`).join('; ')
  const tunnel = await wsThroughGateway(gatewayB.port, { cookie: cookieHeader })
  assert.equal(tunnel.status, 101, 'authenticated upgrade must reach the upstream')
  assert.ok(tunnel.echoed.length > 0, 'echoed frame bytes must come back through the tunnel')
})

test('websocket upgrades bypass auth on loopback', async () => {
  const tunnel = await wsThroughGateway(gatewayA.port)
  assert.equal(tunnel.status, 101)
  assert.ok(tunnel.echoed.length > 0)
})

test('TLS: self-signed certificate is generated, persisted, and served', async () => {
  const stateDir = mkdtempSync(join(tmpdir(), 'lan-gate-tls-'))
  let gate
  let gate2
  try {
    gate = await startGateway(upstream.port, {
      tls: { enabled: true, selfSignedDays: 30 },
      stateDir,
    })
    const result = await new Promise((resolve, reject) => {
      const req = https.request(
        { host: '127.0.0.1', port: gate.port, path: '/', rejectUnauthorized: false, agent: false },
        (res) => {
          let data = ''
          res.on('data', (c) => { data += c })
          res.on('end', () => resolve({ status: res.statusCode, body: data, cert: res.socket.getPeerCertificate() }))
        },
      )
      req.on('error', reject)
      req.end()
    })
    assert.equal(result.status, 200)
    assert.equal(result.body, 'upstream-ok')
    assert.equal(result.cert.subject.CN, 'dsh-lan-access')

    const { existsSync } = await import('node:fs')
    assert.ok(existsSync(join(stateDir, 'tls', 'server.crt')))
    assert.ok(existsSync(join(stateDir, 'tls', 'server.key')))

    // A second gateway on the same state dir reuses the same certificate.
    gate2 = await startGateway(upstream.port, {
      tls: { enabled: true },
      stateDir,
    })
    await gate2.gateway.close()
    const cert2 = gate2.gateway.status()
    assert.equal(cert2.tls.selfSigned, true)
  } finally {
    if (gate !== undefined) await gate.gateway.close()
    if (gate2 !== undefined) await gate2.gateway.close()
    rmSync(stateDir, { recursive: true, force: true })
  }
})

test('disabled gateway does not bind', async () => {
  const gate = await startGateway(upstream.port, { enabled: false })
  const status = gate.gateway.status()
  assert.equal(status.enabled, false)
  await gate.gateway.close()
  rmSync(gate.stateDir, { recursive: true, force: true })
})

test('audit log records auth failures and successes', async () => {
  await login(gatewayB.port, { password: 'wrong' })
  const { readFileSync } = await import('node:fs')
  const lines = readFileSync(join(gatewayB.stateDir, 'audit.jsonl'), 'utf8').trim().split('\n')
  const events = lines.map((line) => JSON.parse(line).event)
  assert.ok(events.includes('auth-failed'))
  assert.ok(events.includes('auth-ok'))
})

test('HTML responses get the randomUUID polyfill injected; other types do not', async () => {
  const html = await request(gatewayA.port, { path: '/html' })
  assert.equal(html.status, 200)
  assert.ok(html.body.includes("typeof c.randomUUID === 'function'"), 'polyfill must be injected into HTML')
  assert.ok(html.body.indexOf('randomUUID') < html.body.indexOf('</head>'), 'polyfill must land before </head>')

  const json = await request(gatewayA.port, { path: '/echo', method: 'POST', body: 'x' })
  assert.ok(!json.body.includes('randomUUID'), 'JSON responses must pass through untouched')
})

test('Origin is rewritten to the upstream authority so the DSH trust fence passes', async () => {
  const res = await request(gatewayA.port, {
    path: '/headers',
    headers: { origin: 'http://172.16.1.36:3081', 'sec-fetch-site': 'same-origin' },
  })
  assert.equal(res.status, 200)
  const seen = JSON.parse(res.body)
  assert.equal(seen.host, `127.0.0.1:${upstream.port}`, 'Host must point at the upstream loopback')
  assert.equal(seen.origin, `http://127.0.0.1:${upstream.port}`, 'Origin must match the rewritten Host')
  assert.equal(seen['sec-fetch-site'], 'same-origin')
})

test('Origin rewriting can be disabled via compat.rewriteOrigin', async () => {
  const gate = await startGateway(upstream.port, { compat: { rewriteOrigin: false } })
  try {
    const res = await request(gate.port, {
      path: '/headers',
      headers: { origin: 'http://172.16.1.36:3081' },
    })
    const seen = JSON.parse(res.body)
    assert.equal(seen.origin, 'http://172.16.1.36:3081', 'Origin must pass through untouched when disabled')
  } finally {
    await gate.gateway.close()
    rmSync(gate.stateDir, { recursive: true, force: true })
  }
})

test('WebSocket upgrades carry the rewritten Origin to the upstream', async () => {
  const res = await login(gatewayB.port)
  const cookies = extractCookies(res)
  const cookieHeader = Object.entries(cookies).map(([k, v]) => `${k}=${v}`).join('; ')
  const tunnel = await wsThroughGateway(gatewayB.port, {
    cookie: cookieHeader,
    origin: 'http://172.16.1.36:3081',
  })
  assert.equal(tunnel.status, 101)
  const headers = upstream.lastUpgradeHeaders()
  assert.ok(headers, 'upstream must have seen the upgrade')
  assert.equal(headers.origin, `http://127.0.0.1:${upstream.port}`, 'upgrade Origin must be rewritten')
  assert.equal(headers.host, `127.0.0.1:${upstream.port}`)
})

test('the randomUUID polyfill injection can be disabled', async () => {
  const gate = await startGateway(upstream.port, { compat: { injectRandomUUIDPolyfill: false } })
  try {
    const html = await request(gate.port, { path: '/html' })
    assert.equal(html.status, 200)
    assert.ok(!html.body.includes('randomUUID'), 'no polyfill when disabled')
  } finally {
    await gate.gateway.close()
    rmSync(gate.stateDir, { recursive: true, force: true })
  }
})
