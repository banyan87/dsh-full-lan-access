// cidr.js — dependency-free IPv4/IPv6 CIDR matching.
//
// Used by the gateway's IP policy. The matcher only ever sees the socket's
// real remote address; proxy headers are never consulted (see policy.js).

import { isIP } from 'node:net'

/**
 * Normalize a socket remote address for policy decisions.
 * - Strips the IPv4-mapped form `::ffff:a.b.c.d` back to IPv4.
 * - Lowercases IPv6 text (no textual compression is applied; byte
 *   comparison below is canonical so this is safe).
 * - Rejects malformed input by returning `null`.
 *
 * @param {string} ip
 * @returns {string | null}
 */
export function normalizeIp(ip) {
  if (typeof ip !== 'string' || ip.length === 0) return null
  let value = ip.trim().toLowerCase()
  const mapped = /^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/.exec(value)
  if (mapped !== null) value = mapped[1]
  const family = isIP(value)
  if (family === 0) return null
  return family === 4 ? value : expandIpv6(value)
}

/**
 * Expand a textual IPv6 address (with `::` compression) into a canonical
 * 8-group lowercase form used for byte parsing.
 * @param {string} ip
 * @returns {string | null}
 */
export function expandIpv6(ip) {
  if (typeof ip !== 'string' || ip.length === 0) return null
  let address = ip
  // Handle IPv4-in-IPv6 suffix: ::1.2.3.4 → ::102:304
  const v4Tail = /^(.*:)(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(address)
  if (v4Tail !== null) {
    const octets = [v4Tail[2], v4Tail[3], v4Tail[4], v4Tail[5]]
      .map((n) => Number.parseInt(n, 10))
    if (octets.some((n) => n < 0 || n > 255)) return null
    address = `${v4Tail[1]}${octets[0].toString(16).padStart(2, '0')}${octets[1].toString(16).padStart(2, '0')}:${octets[2].toString(16).padStart(2, '0')}${octets[3].toString(16).padStart(2, '0')}`
  }
  const halves = address.split('::')
  if (halves.length > 2) return null
  const head = halves[0] === '' ? [] : halves[0].split(':')
  if (halves.length === 2) {
    const tail = halves[1] === '' ? [] : halves[1].split(':')
    const missing = 8 - head.length - tail.length
    if (missing < 1) return null
    for (let i = 0; i < missing; i += 1) head.push('0')
    for (const part of tail) head.push(part)
  }
  if (head.length !== 8) return null
  const groups = head.map((part) => {
    if (!/^[0-9a-f]{1,4}$/.test(part)) return null
    return part.padStart(4, '0')
  })
  if (groups.some((g) => g === null)) return null
  return groups.join(':')
}

/**
 * Parse an IPv4 or IPv6 address string into 16 bytes (IPv4 occupies the last
 * four bytes, IPv4-in-IPv6 style). Returns null for malformed input.
 * @param {string} ip canonical IPv4 or expanded IPv6
 * @returns {Uint8Array | null}
 */
export function ipToBytes(ip) {
  if (isIP(ip) === 4) {
    const octets = ip.split('.').map((n) => Number.parseInt(n, 10))
    const out = new Uint8Array(16)
    for (let i = 0; i < 4; i += 1) out[12 + i] = octets[i]
    return out
  }
  const expanded = expandIpv6(ip)
  if (expanded === null) return null
  const out = new Uint8Array(16)
  let i = 0
  for (const group of expanded.split(':')) {
    out[i] = Number.parseInt(group.slice(0, 2), 16)
    out[i + 1] = Number.parseInt(group.slice(2, 4), 16)
    i += 2
  }
  return out
}

/**
 * Parse a CIDR string like `192.168.1.0/24`, `2001:db8::/32`, `10.0.0.1`
 * (implicit `/32` or `/128`), or the literal `any` (0.0.0.0/0 plus ::/0).
 * @param {string} text
 * @returns {{ family: 4 | 6, base: Uint8Array, prefix: number, text: string } | null}
 */
export function parseCidr(text) {
  if (typeof text !== 'string') return null
  const value = text.trim().toLowerCase()
  if (value === 'any' || value === '*') {
    return { family: 4, base: new Uint8Array(16), prefix: 0, text: value }
  }
  const slash = value.lastIndexOf('/')
  let addr
  let prefix
  if (slash === -1) {
    addr = value
    prefix = isIP(value) === 4 ? 32 : 128
  } else {
    addr = value.slice(0, slash)
    prefix = Number.parseInt(value.slice(slash + 1), 10)
  }
  const family = isIP(addr)
  if (family === 0) return null
  if (!Number.isInteger(prefix) || prefix < 0) return null
  if (family === 4 && prefix > 32) return null
  if (family === 6 && prefix > 128) return null
  const base = ipToBytes(family === 4 ? normalizeIp(addr) : addr)
  if (base === null) return null
  return { family, base, prefix, text: value }
}

/**
 * Test whether a CIDR contains an address. The address is normalized first
 * (IPv4-mapped forms match their IPv4 equivalent).
 * @param {{ family: 4 | 6, base: Uint8Array, prefix: number }} cidr
 * @param {string} ip
 * @returns {boolean}
 */
export function cidrContains(cidr, ip) {
  const normalized = normalizeIp(ip)
  if (normalized === null) return false
  const family = isIP(normalized)
  if (family !== cidr.family) {
    // A v4-mapped v6 cidr cannot match a plain v4 address and vice versa.
    return false
  }
  const bytes = ipToBytes(normalized)
  if (bytes === null) return false
  // IPv4 addresses are stored in the last four bytes of the 16-byte
  // representation (IPv4-mapped layout), so the prefix comparison starts
  // at byte 12 for the IPv4 family.
  const offset = family === 4 ? 12 : 0
  const fullBytes = Math.floor(cidr.prefix / 8)
  const remBits = cidr.prefix % 8
  for (let i = 0; i < fullBytes; i += 1) {
    if (bytes[offset + i] !== cidr.base[offset + i]) return false
  }
  if (remBits > 0) {
    const mask = 0xff << (8 - remBits) & 0xff
    if ((bytes[offset + fullBytes] & mask) !== (cidr.base[offset + fullBytes] & mask)) return false
  }
  return true
}

/**
 * Compose an allow/deny decision from two CIDR lists. Deny always wins.
 * @param {{ allow: string[], deny: string[] }} lists
 * @returns {{ allow: Array<ReturnType<typeof parseCidr>>, deny: Array<ReturnType<typeof parseCidr>> }}
 */
export function buildIpPolicy(lists) {
  const parse = (entries) => {
    const out = []
    for (const entry of entries ?? []) {
      const parsed = parseCidr(entry)
      if (parsed === null) {
        throw new Error(`dsh-lan-access: invalid CIDR "${entry}"`)
      }
      out.push(parsed)
    }
    return out
  }
  const allow = parse(lists.allow)
  const deny = parse(lists.deny)
  return {
    allow,
    deny,
    /**
     * @param {string} ip
     * @returns {'allow' | 'deny' | 'unknown'}
     */
    decide(ip) {
      const normalized = normalizeIp(ip)
      if (normalized === null) return 'unknown'
      for (const cidr of deny) {
        if (cidrContains(cidr, normalized)) return 'deny'
      }
      for (const cidr of allow) {
        if (cidrContains(cidr, normalized)) return 'allow'
      }
      return 'unknown'
    },
    matches(ip, cidrList) {
      const normalized = normalizeIp(ip)
      if (normalized === null) return false
      for (const cidr of cidrList) {
        if (cidrContains(cidr, normalized)) return true
      }
      return false
    },
  }
}

/** True when the address is a loopback address (IPv4 127/8 or IPv6 ::1). */
export function isLoopback(ip) {
  const normalized = normalizeIp(ip)
  if (normalized === null) return false
  if (isIP(normalized) === 4) return /^127\./.test(normalized)
  // The IPv6 loopback is exactly 15 zero bytes plus a trailing 1.
  const bytes = ipToBytes(normalized)
  if (bytes === null) return false
  for (let i = 0; i < 15; i += 1) {
    if (bytes[i] !== 0) return false
  }
  return bytes[15] === 1
}
