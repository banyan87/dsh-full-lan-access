// server.js — the LAN gateway: request pipeline and HTTP(S) listener.
//
// Request flow for every connection:
//   1. capture the real socket address (proxy headers are never trusted)
//   2. reject requests carrying spoofable proxy headers (configurable)
//   3. apply the CIDR allow/deny policy (deny wins)
//   4. loopback bypass: local clients pass straight through (configurable)
//   5. route /__lan_gate/* locally (login, logout, status, CSRF)
//   6. validate the session cookie; unauthenticated clients get a redirect
//      (browsers) or 401 (APIs), then rate-limited
//   7. stream the request to the upstream DSH web server, including
//      WebSocket upgrades
//   8. audit every decision to the JSON-lines audit log

import http from 'node:http'
import https from 'node:https'
import { readFileSync } from 'node:fs'
import { mkdirSync, writeFileSync, chmodSync } from 'node:fs'
import { networkInterfaces } from 'node:os'
import { dirname, join } from 'node:path'
import { createRequire } from 'node:module'
import { buildIpPolicy, isLoopback, normalizeIp } from './cidr.js'
import { verifyPassword } from './scrypt.js'
import { createSessionStore } from './sessions.js'
import { createRateLimiter } from './ratelimit.js'
import { createAuditLog } from './audit.js'
import { createProxy } from './proxy.js'
import { generateSelfSignedCert } from './x509.js'
import { newCsrfToken, renderLoginPage } from './login.js'
import { sendJson } from './httpkit.js'
import { RANDOM_UUID_POLYFILL } from './compat.js'
import {
  authRequiredFor,
  clientIpOf,
  parseCookies,
  presentProxyHeaders,
  requestKind,
  wantsHtml,
} from './policy.js'

const require = createRequire(import.meta.url)
const VERSION = require('../package.json').version

const LOGIN_PATH = '/__lan_gate/login'
const LOGOUT_PATH = '/__lan_gate/logout'
const STATUS_PATH = '/__lan_gate/status'

function send(res, status, body, headers = {}) {
  if (res.headersSent) {
    res.destroy()
    return
  }
  res.writeHead(status, headers)
  res.end(body)
}

function redirect(res, location) {
  send(res, 302, '', { location, 'cache-control': 'no-store' })
}

/**
 * @param {Record<string, any>} config resolved config (see config.js)
 * @param {{ logger?: any, env?: Record<string, string | undefined> }} [options]
 */
export function createGateway(config, options = {}) {
  const logger = options.logger ?? console
  const env = options.env ?? (typeof process !== 'undefined' ? process.env : {})
  const audit = createAuditLog({
    level: config.audit.level,
    filePath: config.audit.file,
    sink: (line) => logger?.info?.(line) ?? console.log(line),
  })
  const ipPolicy = buildIpPolicy({
    allow: config.security.allowCidrs,
    deny: config.security.denyCidrs,
  })
  const sessions = createSessionStore({
    ttlMs: config.session.ttlSec * 1000,
    maxSessions: config.session.maxSessions,
    filePath: config.security.requireAuth ? join(config.stateDir, 'sessions.json') : null,
  })
  const loginLimiter = createRateLimiter({
    max: config.login.maxAttempts,
    windowMs: config.login.windowSec * 1000,
  })
  const generalLimiter = createRateLimiter({
    max: config.rateLimit.maxRequests,
    windowMs: config.rateLimit.windowSec * 1000,
  })
  const proxy = createProxy({
    target: config.upstream,
    timeoutMs: config.proxy.timeoutMs,
    sessionCookieName: config.session.cookieName,
    audit,
    // DSH's /api trust fence compares Origin against the Host it receives;
    // the proxy rewrites Host to the upstream loopback authority, so the
    // Origin is rewritten to match (see lib/compat.js for the rationale).
    originAuthority: config.compat.rewriteOrigin
      ? `${config.upstream.protocol}://${config.upstream.host}:${config.upstream.port}`
      : null,
    // Plain-HTTP LAN origins are not secure contexts, so browsers do not
    // expose crypto.randomUUID(); inject a polyfill into HTML pages.
    htmlInjection: config.compat.injectRandomUUIDPolyfill
      ? { script: RANDOM_UUID_POLYFILL }
      : null,
  })

  const startedAt = Date.now()
  /** @type {import('node:http').Server | null} */
  let server = null
  let boundAddress = null
  let tlsMaterial = null
  /** Non-internal interface addresses sampled at listen time (diagnostics). */
  let lanAddresses = []

  const cookieName = config.session.cookieName
  const csrfCookieName = `${cookieName}_csrf`

  function sessionCookie(token, maxAgeSec) {
    const parts = [
      `${cookieName}=${token}`,
      'Path=/',
      'HttpOnly',
      'SameSite=Lax',
      `Max-Age=${maxAgeSec}`,
    ]
    if (tlsMaterial !== null) parts.push('Secure')
    return parts.join('; ')
  }

  function csrfCookie(token) {
    const parts = [`${csrfCookieName}=${token}`, 'Path=/', 'HttpOnly', 'SameSite=Lax']
    if (tlsMaterial !== null) parts.push('Secure')
    return parts.join('; ')
  }

  function sessionFrom(req) {
    const cookies = parseCookies(req.headers.cookie)
    const token = cookies[cookieName]
    if (typeof token !== 'string' || token.length === 0) return null
    return sessions.verify(token)
  }

  /* ── local endpoint handlers ─────────────────────────────────────────── */

  function handleLoginGet(req, res, ip) {
    const csrf = newCsrfToken()
    const lockout = loginLimiter.peek(ip)
    const retryAfterSec = lockout.allowed ? 0 : Math.max(1, Math.ceil(config.login.lockoutSec / 1000))
    const body = renderLoginPage({
      csrf,
      retryAfterSec,
      branding: 'DeepSeek Harness — LAN Access',
    })
    send(res, 200, body, {
      'content-type': 'text/html; charset=utf-8',
      'cache-control': 'no-store',
      'set-cookie': csrfCookie(csrf),
    })
  }

  function handleLoginPost(req, res, ip) {
    let raw = ''
    req.setEncoding('utf8')
    req.on('data', (chunk) => {
      raw += chunk
      if (raw.length > 16 * 1024) {
        req.destroy()
        return
      }
    })
    req.on('end', () => {
      const lockout = loginLimiter.hit(ip)
      if (!lockout.allowed) {
        audit.warn('auth-locked', { ip, path: LOGIN_PATH })
        const csrf = newCsrfToken()
        const body = renderLoginPage({
          csrf,
          retryAfterSec: Math.max(1, Math.ceil(config.login.lockoutSec / 1000)),
        })
        send(res, 429, body, {
          'content-type': 'text/html; charset=utf-8',
          'cache-control': 'no-store',
          'set-cookie': csrfCookie(csrf),
        })
        return
      }
      const params = new URLSearchParams(raw)
      const cookies = parseCookies(req.headers.cookie)
      const formCsrf = params.get('csrf') ?? ''
      const cookieCsrf = cookies[csrfCookieName] ?? ''
      if (formCsrf.length === 0 || cookieCsrf.length === 0 || formCsrf !== cookieCsrf) {
        audit.warn('csrf-rejected', { ip, path: LOGIN_PATH })
        const csrf = newCsrfToken()
        const body = renderLoginPage({ csrf, error: 'Invalid or missing CSRF token. Please try again.' })
        send(res, 403, body, {
          'content-type': 'text/html; charset=utf-8',
          'cache-control': 'no-store',
          'set-cookie': csrfCookie(csrf),
        })
        return
      }
      const password = params.get('password') ?? ''
      const ok = verifyPassword(password, config.security.passwordHash)
      if (!ok) {
        audit.warn('auth-failed', { ip, path: LOGIN_PATH })
        const csrf = newCsrfToken()
        const body = renderLoginPage({ csrf, error: 'Incorrect password.' })
        send(res, 401, body, {
          'content-type': 'text/html; charset=utf-8',
          'cache-control': 'no-store',
          'set-cookie': csrfCookie(csrf),
        })
        return
      }
      loginLimiter.reset(ip)
      const session = sessions.issue()
      audit.info('auth-ok', { ip, sessionId: session.id })
      send(res, 302, '', {
        location: '/',
        'cache-control': 'no-store',
        'set-cookie': sessionCookie(session.token, config.session.ttlSec),
      })
    })
  }

  function handleLogout(req, res) {
    const cookies = parseCookies(req.headers.cookie)
    const token = cookies[cookieName]
    if (typeof token === 'string') {
      sessions.revoke(token)
      audit.info('logout', { ip: clientIpOf(req).ip })
    }
    send(res, 302, '', {
      location: LOGIN_PATH,
      'set-cookie': `${cookieName}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0`,
      'cache-control': 'no-store',
    })
  }

  function handleStatus(req, res) {
    const now = Date.now()
    const port = boundAddress?.port ?? config.listen.port
    sendJson(res, 200, {
      service: 'dsh-lan-access',
      version: VERSION,
      startedAt: new Date(startedAt).toISOString(),
      uptimeSec: Math.floor((now - startedAt) / 1000),
      // Reachable URLs on non-internal interfaces (diagnostics).
      urls: lanAddresses.map((ip) => `http://${ip.includes(':') ? `[${ip}]` : ip}:${port}`),
      listen: boundAddress === null ? null : {
        host: config.listen.host,
        port: boundAddress.port,
        family: boundAddress.family,
      },
      tls: tlsMaterial === null ? { enabled: false } : {
        enabled: true,
        selfSigned: tlsMaterial.selfSigned,
        subject: tlsMaterial.cert.subject,
        notAfter: tlsMaterial.cert.validTo,
        san: tlsMaterial.cert.subjectAltName ?? '',
      },
      sessions: { count: sessions.count(), max: config.session.maxSessions, ttlSec: config.session.ttlSec },
      security: {
        requireAuth: config.security.requireAuth,
        authConfigured: typeof config.security.passwordHash === 'string' && config.security.passwordHash.length > 0,
        loopbackBypassAuth: config.security.loopbackBypassAuth,
        rejectProxyHeaders: config.security.rejectProxyHeaders,
        allowCidrs: config.security.allowCidrs,
        denyCidrs: config.security.denyCidrs,
      },
      upstream: config.upstream,
      audit: { level: config.audit.level },
    })
  }

  /* ── the request pipeline ────────────────────────────────────────────── */

  async function handleRequest(req, res) {
    try {
      const { ip } = clientIpOf(req)
      if (ip === null) {
        audit.warn('ip-unresolvable', { raw: req.socket.remoteAddress ?? null })
        send(res, 400, 'Bad Request')
        return
      }
      const kind = requestKind(req)
      const path = new URL(req.url ?? '/', 'http://gateway').pathname

      const spoofed = presentProxyHeaders(req)
      if (config.security.rejectProxyHeaders && spoofed.length > 0) {
        audit.warn('proxy-header-rejected', { ip, path, headers: spoofed })
        send(res, 400, 'Bad Request: proxy headers are not accepted')
        return
      }

      const verdict = ipPolicy.decide(ip)
      if (verdict === 'deny') {
        audit.warn('ip-denied', { ip, path })
        send(res, 403, 'Forbidden: address is denied by policy')
        return
      }
      if (verdict === 'unknown') {
        audit.warn('ip-not-allowed', { ip, path })
        send(res, 403, 'Forbidden: address is not allowed by policy')
        return
      }

      const loopback = isLoopback(ip)
      const needsAuth = authRequiredFor({
        ip,
        requireAuth: config.security.requireAuth,
        loopbackBypassAuth: config.security.loopbackBypassAuth,
      })

      // Local gateway endpoints. The login page must always render so users
      // can authenticate; the login POST carries its own per-IP limiter.
      if (path === LOGIN_PATH) {
        if (req.method === 'GET') {
          handleLoginGet(req, res, ip)
          return
        }
        if (req.method === 'POST') {
          handleLoginPost(req, res, ip)
          return
        }
        send(res, 405, 'Method Not Allowed')
        return
      }
      if (path === LOGOUT_PATH) {
        handleLogout(req, res)
        return
      }
      if (path === STATUS_PATH) {
        if (req.method !== 'GET') {
          send(res, 405, 'Method Not Allowed')
          return
        }
        const session = needsAuth ? sessionFrom(req) : null
        if (needsAuth && session === null) {
          audit.warn('status-denied', { ip })
          sendJson(res, 401, { error: 'unauthorized' })
          return
        }
        handleStatus(req, res)
        return
      }

      // Trusted traffic goes upstream without the general limiter: loopback
      // clients and authenticated sessions are authorized users (the CIDR
      // allowlist bounds who can authenticate in the first place). The
      // general limiter only guards the auth gate below.
      if (!needsAuth) {
        audit.debug('proxy-bypass', { ip, path, kind })
        await proxy.proxyHttp(req, res)
        return
      }

      const session = sessionFrom(req)
      if (session !== null) {
        audit.debug('proxy-authed', { ip, path, kind, sessionId: session.id })
        await proxy.proxyHttp(req, res)
        return
      }

      // Unauthenticated non-loopback traffic: the per-IP limiter throttles
      // anonymous floods against the auth gate and the upstream.
      if (config.rateLimit.enabled) {
        const limited = generalLimiter.hit(ip)
        if (!limited.allowed) {
          audit.warn('rate-limited', { ip, path, kind })
          send(res, 429, 'Too Many Requests', { 'retry-after': String(Math.ceil(config.rateLimit.windowSec)) })
          return
        }
      }
      audit.info('auth-required', { ip, path, kind })
      if (wantsHtml(req)) {
        redirect(res, `${LOGIN_PATH}?next=${encodeURIComponent(req.url ?? '/')}`)
      } else {
        sendJson(res, 401, { error: 'unauthorized', login: LOGIN_PATH })
      }
    } catch (err) {
      audit.error('gateway-error', { message: err instanceof Error ? err.message : String(err) })
      if (!res.headersSent) send(res, 500, 'Internal Server Error')
      else res.destroy()
    }
  }

  function handleUpgrade(req, socket, head) {
    const destroy = (status) => {
      try {
        if (status !== undefined) socket.write(`HTTP/1.1 ${status}\r\nConnection: close\r\n\r\n`)
      } catch {
        // ignore
      }
      socket.destroy()
    }
    try {
      const { ip } = clientIpOf(req)
      if (ip === null) {
        destroy(400)
        return
      }
      const spoofed = presentProxyHeaders(req)
      if (config.security.rejectProxyHeaders && spoofed.length > 0) {
        audit.warn('proxy-header-rejected', { ip, path: req.url, kind: 'websocket' })
        destroy(400)
        return
      }
      const verdict = ipPolicy.decide(ip)
      if (verdict !== 'allow') {
        audit.warn(verdict === 'deny' ? 'ip-denied' : 'ip-not-allowed', { ip, path: req.url, kind: 'websocket' })
        destroy(403)
        return
      }
      const needsAuth = authRequiredFor({
        ip,
        requireAuth: config.security.requireAuth,
        loopbackBypassAuth: config.security.loopbackBypassAuth,
      })
      if (needsAuth) {
        const session = sessionFrom(req)
        if (session === null) {
          audit.info('auth-required', { ip, path: req.url, kind: 'websocket' })
          destroy(401)
          return
        }
        audit.debug('proxy-authed', { ip, path: req.url, kind: 'websocket', sessionId: session.id })
      } else {
        audit.debug('proxy-bypass', { ip, path: req.url, kind: 'websocket' })
      }
      proxy.proxyUpgrade(req, socket, head)
    } catch (err) {
      audit.error('gateway-upgrade-error', { message: err instanceof Error ? err.message : String(err) })
      destroy(500)
    }
  }

  /* ── TLS material ────────────────────────────────────────────────────── */

  function loadTls() {
    if (!config.tls.enabled) return null
    if (config.tls.certPath !== null && config.tls.keyPath !== null) {
      const certPem = readFileSync(config.tls.certPath, 'utf8')
      const keyPem = readFileSync(config.tls.keyPath, 'utf8')
      return {
        selfSigned: false,
        certPem,
        keyPem,
        cert: new (require('node:crypto').X509Certificate)(certPem),
      }
    }
    const stateTlsDir = join(config.stateDir, 'tls')
    const certPath = join(stateTlsDir, 'server.crt')
    const keyPath = join(stateTlsDir, 'server.key')
    let certPem
    let keyPem
    try {
      certPem = readFileSync(certPath, 'utf8')
      keyPem = readFileSync(keyPath, 'utf8')
      // Validate what we load rather than trusting stale files.
      new (require('node:crypto').X509Certificate)(certPem)
    } catch {
      const generated = generateSelfSignedCert({
        cn: 'dsh-lan-access',
        days: config.tls.selfSignedDays,
      })
      mkdirSync(stateTlsDir, { recursive: true })
      writeFileSync(certPath, generated.certPem, 'utf8')
      writeFileSync(keyPath, generated.keyPem, 'utf8')
      try {
        chmodSync(keyPath, 0o600)
      } catch {
        // chmod is best-effort (Windows ignores it).
      }
      certPem = generated.certPem
      keyPem = generated.keyPem
    }
    return {
      selfSigned: true,
      certPem,
      keyPem,
      cert: new (require('node:crypto').X509Certificate)(certPem),
    }
  }

  return {
    /**
     * Start listening. Resolves once the socket is bound.
     * @returns {Promise<{ host: string, port: number, family: string }>}
     */
    listen() {
      return new Promise((resolve, reject) => {
        if (!config.enabled) {
          audit.info('disabled', {})
          resolve({ host: config.listen.host, port: config.listen.port, family: 'none' })
          return
        }
        tlsMaterial = loadTls()
        const handler = (req, res) => {
          handleRequest(req, res)
        }
        const onUpgrade = (req, socket, head) => {
          handleUpgrade(req, socket, head)
        }
        server = tlsMaterial === null
          ? http.createServer(handler)
          : https.createServer({ cert: tlsMaterial.certPem, key: tlsMaterial.keyPem }, handler)
        server.on('upgrade', onUpgrade)
        server.once('error', reject)
        server.listen(config.listen.port, config.listen.host, () => {
          server.off('error', reject)
          const address = server.address()
          boundAddress = typeof address === 'object' && address !== null
            ? { port: address.port, family: address.family }
            : null
          for (const list of Object.values(networkInterfaces())) {
            for (const iface of list ?? []) {
              if (!iface.internal) lanAddresses.push(iface.address)
            }
          }
          lanAddresses.sort()
          const port2 = boundAddress?.port ?? config.listen.port
          audit.info('listening', {
            host: config.listen.host,
            port: port2,
            tls: tlsMaterial !== null,
            selfSigned: tlsMaterial?.selfSigned ?? false,
            upstream: `${config.upstream.protocol}://${config.upstream.host}:${config.upstream.port}`,
            addresses: lanAddresses.map((ip) => `http://${ip.includes(':') ? `[${ip}]` : ip}:${port2}`),
          })
          resolve({
            host: config.listen.host,
            port: boundAddress?.port ?? config.listen.port,
            family: String(address?.family ?? ''),
          })
        })
      })
    },

    /** Stop the gateway: close the listener, sockets, and audit log. */
    close() {
      return new Promise((resolve) => {
        audit.info('stopping', {})
        proxy.close()
        audit.close()
        if (server === null) {
          resolve()
          return
        }
        server.closeAllConnections()
        server.close(() => resolve())
      })
    },

    /** Sanitized status snapshot for the DSH service API. */
    status() {
      const port = boundAddress?.port ?? config.listen.port
      return {
        enabled: config.enabled,
        version: VERSION,
        startedAt,
        listen: boundAddress,
        // Reachable URLs on non-internal interfaces (diagnostics: the URL
        // a LAN client should open, e.g. over a VPN adapter).
        urls: lanAddresses.map((ip) => `http://${ip.includes(':') ? `[${ip}]` : ip}:${port}`),
        sessions: { count: sessions.count(), max: config.session.maxSessions },
        upstream: { ...config.upstream },
        tls: {
          enabled: config.tls.enabled,
          selfSigned: tlsMaterial?.selfSigned ?? null,
        },
      }
    },

    /** Revoke one session by its token. */
    revokeSession(token) {
      return sessions.revoke(token)
    },

    /** Revoke one session by its persisted id (sha256 of the token). */
    revokeSessionById(id) {
      return sessions.revokeById(id)
    },

    /** List live sessions (ids + expiry only). */
    sessions() {
      return sessions.list()
    },

    audit,
    ipPolicy,
  }
}
