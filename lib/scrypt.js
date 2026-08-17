// scrypt.js — password hashing and verification.
//
// Hash encoding (compatible with the DSH `lan-gate.json` convention):
//
//   scrypt$N$r$p$saltBase64$hashBase64
//
// Defaults follow OWASP guidance for interactive logins: N=16384, r=8, p=1,
// 16-byte random salt, 32-byte derived key. Verification uses a constant-time
// compare and never throws on malformed input (returns false).

import { randomBytes, scryptSync, timingSafeEqual } from 'node:crypto'

const PREFIX = 'scrypt$'
const DEFAULT_N = 16384
const DEFAULT_R = 8
const DEFAULT_P = 1
const KEYLEN = 32
const SALT_BYTES = 16

/**
 * Hash a password into the `scrypt$N$r$p$salt$hash` string format.
 * @param {string} password
 * @param {{ N?: number, r?: number, p?: number, keylen?: number }} [options]
 * @returns {string}
 */
export function hashPassword(password, options = {}) {
  if (typeof password !== 'string') {
    throw new TypeError('password must be a string')
  }
  const N = options.N ?? DEFAULT_N
  const r = options.r ?? DEFAULT_R
  const p = options.p ?? DEFAULT_P
  const keylen = options.keylen ?? KEYLEN
  const salt = randomBytes(SALT_BYTES)
  const derived = scryptSync(password, salt, keylen, { N, r, p, maxmem: 128 * N * r * 2 })
  return [
    'scrypt',
    String(N),
    String(r),
    String(p),
    salt.toString('base64'),
    derived.toString('base64'),
  ].join('$')
}

/**
 * Parse an encoded hash into its components.
 * @param {string} encoded
 * @returns {{ N: number, r: number, p: number, salt: Buffer, hash: Buffer } | null}
 */
export function parseHash(encoded) {
  if (typeof encoded !== 'string' || !encoded.startsWith(PREFIX)) return null
  const parts = encoded.slice(PREFIX.length).split('$')
  if (parts.length !== 5) return null
  const [nText, rText, pText, saltText, hashText] = parts
  const N = Number.parseInt(nText, 10)
  const r = Number.parseInt(rText, 10)
  const p = Number.parseInt(pText, 10)
  if (![N, r, p].every(Number.isInteger) || N < 2 || r < 1 || p < 1) return null
  let salt
  let hash
  try {
    salt = Buffer.from(saltText, 'base64')
    hash = Buffer.from(hashText, 'base64')
  } catch {
    return null
  }
  if (salt.length === 0 || hash.length === 0) return null
  return { N, r, p, salt, hash }
}

/**
 * Verify a password against an encoded hash. Never throws; returns false for
 * malformed hashes.
 * @param {string} password
 * @param {string} encoded
 * @returns {boolean}
 */
export function verifyPassword(password, encoded) {
  if (typeof password !== 'string') return false
  const parsed = parseHash(encoded)
  if (parsed === null) return false
  try {
    const derived = scryptSync(password, parsed.salt, parsed.hash.length, {
      N: parsed.N,
      r: parsed.r,
      p: parsed.p,
      maxmem: 128 * parsed.N * parsed.r * 2,
    })
    return derived.length === parsed.hash.length
      && timingSafeEqual(derived, parsed.hash)
  } catch {
    return false
  }
}
