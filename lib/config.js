// config.js — config resolution, defaults, and validation.
//
// The gateway fails closed: invalid CIDRs, a malformed password hash, or
// `requireAuth` without a hash all prevent startup with a clear error.

import { homedir } from 'node:os'
import { join } from 'node:path'
import { parseCidr } from './cidr.js'
import { parseHash } from './scrypt.js'

export const DEFAULTS = {
  enabled: true,
  listen: { host: '0.0.0.0', port: 3081 },
  upstream: { protocol: 'http', host: '127.0.0.1', port: 3080 },
  security: {
    allowCidrs: [
      '127.0.0.0/8',
      '::1/128',
      '10.0.0.0/8',
      '172.16.0.0/12',
      '192.168.0.0/16',
      'fc00::/7',
      'fe80::/10',
    ],
    denyCidrs: [],
    requireAuth: true,
    passwordHash: null,
    loopbackBypassAuth: true,
    rejectProxyHeaders: true,
  },
  session: { ttlSec: 7 * 24 * 60 * 60, maxSessions: 64, cookieName: 'dsh_lan_session' },
  login: { maxAttempts: 5, windowSec: 15 * 60, lockoutSec: 15 * 60 },
  rateLimit: { enabled: true, maxRequests: 120, windowSec: 60 },
  tls: { enabled: false, certPath: null, keyPath: null, selfSignedDays: 825 },
  stateDir: null,
  audit: { file: null, level: 'info' },
  proxy: { timeoutMs: 30_000 },
  compat: {
    rewriteOrigin: true,
    injectRandomUUIDPolyfill: true,
  },
}

function defaultStateDir(env) {
  const home = env?.DSH_HOME ?? homedir()
  return join(home, 'lan-access')
}

function mergeInto(target, source) {
  if (source === undefined || source === null) return target
  if (typeof source === 'object' && !Array.isArray(source)) {
    for (const [key, value] of Object.entries(source)) {
      if (value === undefined) continue
      if (
        target[key] !== undefined
        && typeof target[key] === 'object'
        && !Array.isArray(target[key])
        && typeof value === 'object'
        && !Array.isArray(value)
      ) {
        target[key] = mergeInto({ ...target[key] }, value)
      } else {
        target[key] = value
      }
    }
    return target
  }
  return source
}

function validatePort(value, label) {
  // 0 means "let the OS assign an ephemeral port" (useful for tests and
  // multi-instance deployments).
  if (!Number.isInteger(value) || value < 0 || value > 65535) {
    throw new Error(`dsh-lan-access: ${label} must be an integer in 0..65535, got ${value}`)
  }
}

/**
 * Merge raw (possibly partial) config over defaults and validate.
 * @param {Record<string, any>} raw
 * @param {{ env?: Record<string, string | undefined> }} [options]
 * @returns {Record<string, any>}
 */
export function resolveConfig(raw = {}, options = {}) {
  const env = options.env ?? (typeof process !== 'undefined' ? process.env : {})
  const config = mergeInto(mergeInto({}, DEFAULTS), raw)

  if (config.enabled === false) return config

  validatePort(config.listen.port, 'listen.port')
  validatePort(config.upstream.port, 'upstream.port')
  if (!['http', 'https'].includes(config.upstream.protocol)) {
    throw new Error(`dsh-lan-access: upstream.protocol must be "http" or "https", got ${config.upstream.protocol}`)
  }
  if (typeof config.listen.host !== 'string' || config.listen.host.length === 0) {
    throw new Error('dsh-lan-access: listen.host must be a non-empty string')
  }
  if (typeof config.upstream.host !== 'string' || config.upstream.host.length === 0) {
    throw new Error('dsh-lan-access: upstream.host must be a non-empty string')
  }

  for (const cidr of [...config.security.allowCidrs, ...config.security.denyCidrs]) {
    if (parseCidr(cidr) === null) {
      throw new Error(`dsh-lan-access: invalid CIDR "${cidr}" in security.allowCidrs/denyCidrs`)
    }
  }

  if (config.security.requireAuth) {
    if (typeof config.security.passwordHash !== 'string' || config.security.passwordHash.length === 0) {
      throw new Error(
        'dsh-lan-access: security.requireAuth is true but security.passwordHash is not set. '
        + 'Generate one with: dsh-lan-gate hash-password',
      )
    }
    if (parseHash(config.security.passwordHash) === null) {
      throw new Error('dsh-lan-access: security.passwordHash is malformed (expected scrypt$N$r$p$salt$hash)')
    }
  }

  for (const [key, value] of Object.entries(config.login)) {
    if (!Number.isInteger(value) || value < 1) {
      throw new Error(`dsh-lan-access: login.${key} must be a positive integer, got ${value}`)
    }
  }
  if (!Number.isInteger(config.session.ttlSec) || config.session.ttlSec < 60) {
    throw new Error(`dsh-lan-access: session.ttlSec must be >= 60, got ${config.session.ttlSec}`)
  }
  if (!Number.isInteger(config.session.maxSessions) || config.session.maxSessions < 1) {
    throw new Error(`dsh-lan-access: session.maxSessions must be >= 1, got ${config.session.maxSessions}`)
  }
  if (!Number.isInteger(config.rateLimit.maxRequests) || config.rateLimit.maxRequests < 1) {
    throw new Error(`dsh-lan-access: rateLimit.maxRequests must be >= 1, got ${config.rateLimit.maxRequests}`)
  }
  if (!Number.isInteger(config.proxy.timeoutMs) || config.proxy.timeoutMs < 100) {
    throw new Error(`dsh-lan-access: proxy.timeoutMs must be >= 100, got ${config.proxy.timeoutMs}`)
  }
  if (!['error', 'warn', 'info', 'debug'].includes(config.audit.level)) {
    throw new Error(`dsh-lan-access: audit.level must be one of error|warn|info|debug, got ${config.audit.level}`)
  }
  if (config.tls.enabled) {
    if (Boolean(config.tls.certPath) !== Boolean(config.tls.keyPath)) {
      throw new Error('dsh-lan-access: tls.certPath and tls.keyPath must be set together')
    }
  }
  for (const [key, value] of Object.entries(config.compat)) {
    if (typeof value !== 'boolean') {
      throw new Error(`dsh-lan-access: compat.${key} must be a boolean, got ${value}`)
    }
  }

  if (typeof config.stateDir !== 'string' || config.stateDir.length === 0) {
    config.stateDir = defaultStateDir(env)
  }

  return config
}

/**
 * A sanitized view of the resolved config, safe to expose over the status
 * endpoint: never includes the password hash.
 * @param {Record<string, any>} config
 * @returns {Record<string, any>}
 */
export function publicConfig(config) {
  return {
    enabled: config.enabled,
    listen: { host: config.listen.host, port: config.listen.port },
    upstream: { protocol: config.upstream.protocol, host: config.upstream.host, port: config.upstream.port },
    security: {
      allowCidrs: [...config.security.allowCidrs],
      denyCidrs: [...config.security.denyCidrs],
      requireAuth: config.security.requireAuth,
      authConfigured: typeof config.security.passwordHash === 'string' && config.security.passwordHash.length > 0,
      loopbackBypassAuth: config.security.loopbackBypassAuth,
      rejectProxyHeaders: config.security.rejectProxyHeaders,
    },
    session: { ttlSec: config.session.ttlSec, maxSessions: config.session.maxSessions },
    login: { ...config.login },
    rateLimit: { ...config.rateLimit },
    tls: {
      enabled: config.tls.enabled,
      certPath: config.tls.certPath,
      keyPath: config.tls.keyPath,
      selfSigned: config.tls.certPath === null,
    },
    audit: { level: config.audit.level, file: config.audit.file },
    compat: { ...config.compat },
  }
}
