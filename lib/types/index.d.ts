/**
 * Type declarations for dsh-full-lan-access — the secure LAN gateway
 * plugin for DeepSeek Harness.
 *
 * The plugin is a Cordis `Service` named `lanAccess`. Install it through a
 * profile composition row:
 *
 *   - id: lan-access
 *     name: 'dsh-full-lan-access'
 *     config: { ... }
 */

import { Service } from '@deepseek-ai/cordis'
import type { Schema } from '@deepseek-ai/schemastery'

export interface ListenConfig {
  /** Interface to bind. Default `'0.0.0.0'`. */
  host?: string
  /** Gateway port; 0 lets the OS pick an ephemeral port. Default 3081. */
  port?: number
}

export interface UpstreamConfig {
  /** Scheme of the DSH web server. Default `'http'`. */
  protocol?: 'http' | 'https'
  /** DSH bind address. Default `'127.0.0.1'`. */
  host?: string
  /** DSH bind port. Default 3080. */
  port?: number
}

export interface SecurityConfig {
  /** Addresses permitted through the gateway. */
  allowCidrs?: string[]
  /** Addresses always rejected; deny wins over allow. */
  denyCidrs?: string[]
  /** Master switch for password authentication. Default true. */
  requireAuth?: boolean
  /** `scrypt$N$r$p$salt$hash` from `dsh-lan-gate hash-password`. Required when requireAuth is true. */
  passwordHash?: string | null
  /** Loopback clients skip authentication. Default true. */
  loopbackBypassAuth?: boolean
  /** Reject requests carrying spoofable proxy headers. Default true. */
  rejectProxyHeaders?: boolean
}

export interface SessionConfig {
  /** Session lifetime in seconds. Default 604800 (7 days). */
  ttlSec?: number
  /** Maximum concurrent sessions; oldest evicted beyond this. Default 64. */
  maxSessions?: number
  /** Session cookie name. Default `'dsh_lan_session'`. */
  cookieName?: string
}

export interface LoginConfig {
  /** Failed attempts allowed per IP within the window. Default 5. */
  maxAttempts?: number
  /** Sliding window for attempts, seconds. Default 900. */
  windowSec?: number
  /** Lockout duration, seconds. Default 900. */
  lockoutSec?: number
}

export interface RateLimitConfig {
  /** General per-IP request throttle. Default true. */
  enabled?: boolean
  /** Requests per IP per window. Default 120. */
  maxRequests?: number
  /** Throttle window, seconds. Default 60. */
  windowSec?: number
}

export interface TlsConfig {
  /** Serve HTTPS. Default false. */
  enabled?: boolean
  /** PEM certificate file; must be set with keyPath. */
  certPath?: string | null
  /** PEM private key file; must be set with certPath. */
  keyPath?: string | null
  /** Validity of the auto-generated self-signed certificate, days. Default 825. */
  selfSignedDays?: number
}

export interface AuditConfig {
  /** Append JSON-lines audit events to this file. Default null. */
  file?: string | null
  /** Verbosity for the DSH logger sink. Default `'info'`. */
  level?: 'error' | 'warn' | 'info' | 'debug'
}

export interface ProxyConfig {
  /** Upstream request timeout, ms. Default 30000. */
  timeoutMs?: number
}

export interface LanAccessConfig {
  /** Master switch. Default true. */
  enabled?: boolean
  listen?: ListenConfig
  upstream?: UpstreamConfig
  security?: SecurityConfig
  session?: SessionConfig
  login?: LoginConfig
  rateLimit?: RateLimitConfig
  tls?: TlsConfig
  /** State directory (sessions, TLS material, audit). Default `$DSH_HOME/lan-access`. */
  stateDir?: string | null
  audit?: AuditConfig
  proxy?: ProxyConfig
}

export interface GatewaySession {
  /** SHA-256 digest of the token (the persisted id). */
  id: string
  /** Expiry, epoch milliseconds. */
  exp: number
}

export interface GatewayStatus {
  enabled: boolean
  version: string
  startedAt: number
  listen: { port: number; family: string } | null
  sessions: { count: number; max: number }
  upstream: UpstreamConfig
  tls: { enabled: boolean; selfSigned: boolean | null }
}

/** The Cordis service registered by this plugin. */
export declare class LanAccess extends Service {
  static Config: Schema<LanAccessConfig>
  readonly resolved: LanAccessConfig

  /** Start listening (rejects the fiber on bind failure — fail closed). */
  [Service.init](): Promise<void>

  /** Sanitized runtime status (never includes the password hash). */
  status(): GatewayStatus

  /** List live gateway sessions (id + expiry). */
  sessions(): GatewaySession[]

  /** Revoke one session by its token. */
  revokeSession(token: string): boolean

  /** Revoke one session by its persisted id (sha256 of the token). */
  revokeSessionById(id: string): boolean
}

/** The schemastery Config schema validated against every row config. */
export declare const Config: Schema<LanAccessConfig>

export default LanAccess
