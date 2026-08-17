// scripts/smoke-live.mjs — live smoke test against a real DSH web server.
//
// Starts the gateway on 0.0.0.0:<port> proxying to the real DSH instance,
// then verifies the security chain with real sockets:
//   1. loopback access bypasses authentication
//   2. LAN clients (real non-loopback IP) are challenged
//   3. the login flow issues a session cookie that unlocks proxying
//   4. spoofable proxy headers are rejected
//   5. unauthenticated WebSocket upgrades are rejected
//
// Usage: node scripts/smoke-live.mjs [--port 3081] [--upstream http://127.0.0.1:3080]
// The password used is "smoke-test-password" (generated fresh each run).

import http from 'node:http'
import net from 'node:net'
import { networkInterfaces } from 'node:os'
import { resolveConfig } from '../lib/config.js'
import { createGateway } from '../lib/server.js'
import { hashPassword } from '../lib/scrypt.js'

const PASSWORD = process.env.SMOKE_PASSWORD ?? 'smoke-test-password'
const HASH = hashPassword(PASSWORD)

const args = process.argv.slice(2)
const port = Number(args.find((a) => a.startsWith('--port='))?.split('=')[1] ?? 3081)
const upstreamUrl = new URL(args.find((a) => a.startsWith('--upstream='))?.split('=')[1] ?? 'http://127.0.0.1:3080')

let failures = 0
function check(name, ok, detail = '') {
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${detail ? ` — ${detail}` : ''}`)
  if (!ok) failures += 1
}

function request(target, { path = '/', method = 'GET', headers = {}, body } = {}) {
  return new Promise((resolve, reject) => {
    const u = new URL(target)
    const req = http.request({
      protocol: u.protocol,
      hostname: u.hostname,
      port: u.port || undefined,
      path,
      method,
      headers,
      agent: false,
    }, (res) => {
      let data = ''
      res.on('data', (c) => { data += c })
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: data }))
    })
    req.on('error', reject)
    if (body !== undefined) req.write(body)
    req.end()
  })
}

async function login(target) {
  const page = await request(target, { path: '/__lan_gate/login' })
  const setCookies = Array.isArray(page.headers['set-cookie']) ? page.headers['set-cookie'] : [page.headers['set-cookie']]
  const csrfCookie = setCookies.map((s) => s.split(';')[0]).find((s) => s.startsWith('dsh_lan_session_csrf='))
  const csrf = csrfCookie?.split('=')[1]
  if (!csrf) return null
  const body = new URLSearchParams({ csrf, password: PASSWORD }).toString()
  const res = await request(target, {
    path: '/__lan_gate/login',
    method: 'POST',
    headers: {
      'content-type': 'application/x-www-form-urlencoded',
      cookie: csrfCookie,
    },
    body,
  })
  const session = (Array.isArray(res.headers['set-cookie']) ? res.headers['set-cookie'] : [res.headers['set-cookie']])
    .map((s) => s.split(';')[0])
    .find((s) => s.startsWith('dsh_lan_session='))
  return session ?? null
}

function wsUpgrade(host, port, { cookie, path = '/api/events.mux' } = {}) {
  return new Promise((resolve) => {
    const timer = setTimeout(() => {
      socket.destroy()
      resolve(0)
    }, 8000)
    const socket = net.connect(port, host)
    const headers = [
      `GET ${path} HTTP/1.1`,
      `Host: ${host}:${port}`,
      'Upgrade: websocket',
      'Connection: Upgrade',
      'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==',
      'Sec-WebSocket-Version: 13',
    ]
    if (cookie) headers.push(`Cookie: ${cookie}`)
    let buf = Buffer.alloc(0)
    socket.on('data', (chunk) => {
      buf = Buffer.concat([buf, chunk])
      const end = buf.indexOf('\r\n\r\n')
      if (end !== -1) {
        const status = Number(/^HTTP\/1\.1 (\d{3})/.exec(buf.slice(0, end).toString('latin1'))?.[1] ?? 0)
        clearTimeout(timer)
        resolve(status)
        socket.destroy()
      }
    })
    socket.on('connect', () => socket.write(`${headers.join('\r\n')}\r\n\r\n`))
    socket.on('error', () => {
      clearTimeout(timer)
      resolve(0)
    })
  })
}

function lanAddresses() {
  const out = []
  for (const list of Object.values(networkInterfaces())) {
    for (const iface of list ?? []) {
      if (!iface.internal && iface.family === 'IPv4') out.push(iface.address)
    }
  }
  return out
}

const config = resolveConfig({
  listen: { host: '0.0.0.0', port },
  upstream: { host: upstreamUrl.hostname, port: Number(upstreamUrl.port) },
  security: { passwordHash: HASH },
  stateDir: null, // default under DSH_HOME or the home directory
})

const gateway = createGateway(config, { logger: console })
const bound = await gateway.listen()
console.log(`\ngateway listening on ${bound.host}:${bound.port} → upstream ${upstreamUrl}\n`)

try {
  const loopback = `http://127.0.0.1:${bound.port}`

  // 1. Loopback bypass.
  const local = await request(loopback, { path: '/' })
  check('loopback request is proxied without auth', local.status === 200, `status=${local.status}`)

  // 2. Real LAN source address requires authentication.
  const lans = lanAddresses()
  if (lans.length === 0) {
    check('LAN address present (skip auth-challenge check)', false, 'no non-loopback IPv4 interface found')
  } else {
    for (const lan of lans) {
      const target = `http://${lan}:${bound.port}`
      const challenged = await request(target, { path: '/' })
      check(
        `LAN client ${lan} is challenged`,
        challenged.status === 302 && challenged.headers.location?.startsWith('/__lan_gate/login'),
        `status=${challenged.status}, location=${challenged.headers.location}`,
      )

      const api = await request(target, { path: '/api/status', headers: { accept: 'application/json' } })
      check(`LAN client ${lan} API gets 401 JSON`, api.status === 401, `status=${api.status}`)

      // 3. Login flow.
      const session = await login(target)
      check(`LAN client ${lan} login issues a session`, typeof session === 'string', session ? 'session cookie received' : 'no session cookie')

      if (session) {
        const authed = await request(target, { path: '/', headers: { cookie: session } })
        check(`LAN client ${lan} proxies after login`, authed.status === 200, `status=${authed.status}`)

        const status = await request(target, { path: '/__lan_gate/status', headers: { cookie: session, accept: 'application/json' } })
        let parsed = null
        try { parsed = JSON.parse(status.body) } catch { /* ignore */ }
        check(`LAN client ${lan} status endpoint works`, status.status === 200 && parsed?.service === 'dsh-lan-access', `status=${status.status}`)

        const ws = await wsUpgrade(lan, bound.port, { cookie: session })
        check(`LAN client ${lan} authenticated WebSocket upgrade proxied`, ws === 101, `status=${ws}`)
      }

      const wsDenied = await wsUpgrade(lan, bound.port)
      check(`LAN client ${lan} unauthenticated WebSocket upgrade rejected`, wsDenied === 401, `status=${wsDenied}`)
    }
  }

  // 4. Proxy headers rejected.
  const spoofed = await request(loopback, { path: '/', headers: { 'x-forwarded-for': '203.0.113.7' } })
  check('proxy headers rejected', spoofed.status === 400, `status=${spoofed.status}`)

  console.log(failures === 0 ? '\nSMOKE TEST PASSED' : `\nSMOKE TEST FAILED (${failures} failure(s))`)
} finally {
  await gateway.close()
}

process.exitCode = failures === 0 ? 0 : 1
