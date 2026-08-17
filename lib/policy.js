// policy.js — pure request-policy helpers.
//
// All functions here are side-effect free so they can be unit-tested without
// sockets. The gateway's request pipeline (server.js) composes them.

import { isIP } from 'node:net'
import { isLoopback, normalizeIp } from './cidr.js'

/** Headers that would let a client spoof its apparent source address. */
const PROXY_HEADER_NAMES = [
  'forwarded',
  'x-forwarded-for',
  'x-forwarded-host',
  'x-forwarded-proto',
  'x-real-ip',
  'x-originating-ip',
  'x-client-ip',
  'via',
]

/**
 * The client IP is always the socket's real remote address. The gateway never
 * trusts any proxy header; when `rejectProxyHeaders` is enabled it actively
 * rejects requests that carry them (defense in depth against misconfigured
 * upstream proxies and spoofing attempts).
 *
 * @param {import('node:http').IncomingMessage} req
 * @returns {{ ip: string | null, rawIp: string | null }}
 */
export function clientIpOf(req) {
  const raw = req.socket?.remoteAddress ?? null
  return { ip: normalizeIp(raw), rawIp: raw }
}

/**
 * @param {import('node:http').IncomingMessage} req
 * @returns {string[]} present proxy header names (lowercase)
 */
export function presentProxyHeaders(req) {
  const found = []
  const headers = req.headers ?? {}
  for (const name of PROXY_HEADER_NAMES) {
    if (headers[name] !== undefined) found.push(name)
  }
  return found
}

/**
 * Categorize a request for audit purposes.
 * @param {import('node:http').IncomingMessage} req
 * @returns {string}
 */
export function requestKind(req) {
  const upgrade = req.headers.upgrade
  if (upgrade !== undefined && String(upgrade).toLowerCase() === 'websocket') return 'websocket'
  return 'http'
}

/**
 * Decide whether authentication is required for this client.
 * @param {{ ip: string | null, loopbackBypassAuth: boolean, requireAuth: boolean }} options
 * @returns {boolean}
 */
export function authRequiredFor(options) {
  if (!options.requireAuth) return false
  if (options.loopbackBypassAuth && options.ip !== null && isLoopback(options.ip)) {
    return false
  }
  return true
}

/**
 * Safe cookie parse (no external dependency). Returns a plain object of
 * name → value. Values are not URL-decoded beyond standard cookie syntax.
 * @param {string | undefined} header
 * @returns {Record<string, string>}
 */
export function parseCookies(header) {
  const out = {}
  if (typeof header !== 'string' || header.length === 0) return out
  for (const part of header.split(';')) {
    const eq = part.indexOf('=')
    if (eq === -1) continue
    const name = part.slice(0, eq).trim()
    let value = part.slice(eq + 1).trim()
    if (value.startsWith('"') && value.endsWith('"') && value.length >= 2) {
      value = value.slice(1, -1)
    }
    if (name.length > 0) out[name] = value
  }
  return out
}

/**
 * @param {import('node:http').IncomingMessage} req
 * @returns {boolean} true when the request looks like it comes from a browser
 *   (used to decide between a redirect and a 401 JSON body).
 */
export function wantsHtml(req) {
  const accept = req.headers.accept ?? ''
  return accept.includes('text/html') || accept === '*' || accept === ''
}

/** Hop-by-hop headers that must never be forwarded verbatim. */
export const HOP_BY_HOP = new Set([
  'connection',
  'keep-alive',
  'proxy-authenticate',
  'proxy-authorization',
  'te',
  'trailer',
  'transfer-encoding',
  'upgrade',
])

/**
 * Copy request headers for proxying: strips hop-by-hop headers and the
 * cookie for the gateway's own session name; preserves everything else.
 *
 * DSH's `/api` trust fence requires the Origin header to match the Host it
 * receives. The proxy rewrites Host to the upstream loopback authority, so
 * `originAuthority` rewrites a present Origin to the same authority —
 * otherwise every request carrying an Origin (POST/fetch/WebSocket
 * upgrades) would be rejected by the fence with 403 and privileged RPCs
 * (settings, plugin inventory, model discovery) would break for LAN
 * clients. Pass `null` to leave Origin untouched.
 *
 * @param {import('node:http').IncomingMessage} req
 * @param {string} sessionCookieName
 * @param {{ originAuthority?: string | null }} [options]
 * @returns {Record<string, string>}
 */
export function forwardableHeaders(req, sessionCookieName, options = {}) {
  const out = {}
  for (const [name, value] of Object.entries(req.headers)) {
    if (HOP_BY_HOP.has(name)) continue
    if (name === 'host') continue // reset by the proxy for the upstream
    if (name === 'origin' && typeof options.originAuthority === 'string') {
      out.origin = options.originAuthority
      continue
    }
    if (name === 'cookie' && typeof value === 'string') {
      const cookies = parseCookies(value)
      delete cookies[sessionCookieName]
      delete cookies[`${sessionCookieName}_csrf`]
      const rest = Object.entries(cookies)
        .map(([n, v]) => `${n}=${v}`)
        .join('; ')
      if (rest.length > 0) out.cookie = rest
      continue
    }
    out[name] = String(value)
  }
  return out
}

/** Public re-export used by tests and the CLI. */
export { isIP, isLoopback }
