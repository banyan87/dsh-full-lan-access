// x509.js — dependency-free self-signed X.509 v3 certificate generation.
//
// Generates an ECDSA P-256 server certificate so the gateway can offer TLS
// out of the box without requiring OpenSSL or external tooling. The
// certificate includes DNS `localhost` plus every non-internal interface
// address as subjectAltName entries, and carries serverAuth extended key
// usage. Verify with `crypto.X509Certificate` in tests and `openssl x509`
// in operations.

import { generateKeyPairSync, randomBytes, sign } from 'node:crypto'
import { networkInterfaces } from 'node:os'

/* ── minimal DER encoder ─────────────────────────────────────────────────── */

function encodeOid(oid) {
  const parts = oid.split('.').map((n) => Number.parseInt(n, 10))
  const out = []
  const pushBase128 = (value) => {
    const bytes = [value & 0x7f]
    value = Math.floor(value / 128)
    while (value > 0) {
      bytes.unshift((value & 0x7f) | 0x80)
      value = Math.floor(value / 128)
    }
    out.push(...bytes)
  }
  pushBase128(parts[0] * 40 + parts[1])
  for (let i = 2; i < parts.length; i += 1) pushBase128(parts[i])
  return Buffer.from(out)
}

function derLength(n) {
  if (n < 0x80) return Buffer.from([n])
  const bytes = []
  while (n > 0) {
    bytes.unshift(n & 0xff)
    n = Math.floor(n / 256)
  }
  return Buffer.from([0x80 | bytes.length, ...bytes])
}

function tlv(tag, content) {
  const body = Buffer.isBuffer(content) ? content : Buffer.from(content)
  return Buffer.concat([Buffer.from([tag]), derLength(body.length), body])
}

const seq = (children) => tlv(0x30, Buffer.concat(children))
const setOf = (children) => tlv(0x31, Buffer.concat(children))

function oid(oidStr) {
  return tlv(0x06, encodeOid(oidStr))
}

function integer(bytes) {
  let body = Buffer.from(bytes)
  while (body.length > 1 && body[0] === 0) body = body.subarray(1)
  if (body[0] & 0x80) body = Buffer.concat([Buffer.from([0x00]), body])
  return tlv(0x02, body)
}

function utf8String(text) {
  return tlv(0x0c, Buffer.from(text, 'utf8'))
}

function bitString(bytes, unused = 0) {
  return tlv(0x03, Buffer.concat([Buffer.from([unused]), Buffer.from(bytes)]))
}

function octetString(bytes) {
  return tlv(0x04, bytes)
}

function utcTime(date) {
  const pad = (n) => String(n).padStart(2, '0')
  const text = [
    pad(date.getUTCFullYear() % 100),
    pad(date.getUTCMonth() + 1),
    pad(date.getUTCDate()),
    pad(date.getUTCHours()),
    pad(date.getUTCMinutes()),
    pad(date.getUTCSeconds()),
    'Z',
  ].join('')
  return tlv(0x17, Buffer.from(text, 'ascii'))
}

function explicit(contextTag, content) {
  return tlv(0xa0 | contextTag, content)
}

function boolean(value) {
  return tlv(0x01, value ? [0xff] : [0x00])
}

function name(cn) {
  return seq([setOf([seq([oid('2.5.4.3'), utf8String(cn)])])])
}

const ECDSA_SHA256_ALG = seq([oid('1.2.840.10045.4.3.2')])
const EC_PUBLIC_KEY_ALG = seq([oid('1.2.840.10045.2.1'), oid('1.2.840.10045.3.1.7')])

function extension(extId, critical, value) {
  const children = [oid(extId)]
  if (critical) children.push(boolean(true))
  children.push(octetString(value))
  return seq(children)
}

function pem(label, der) {
  const base64 = der.toString('base64').match(/.{1,64}/g).join('\n')
  return `-----BEGIN ${label}-----\n${base64}\n-----END ${label}-----`
}

/* ── certificate generation ──────────────────────────────────────────────── */

/**
 * Collect candidate subjectAltName entries from local interfaces.
 * @returns {string[]} hostnames and IP literals
 */
export function localSanEntries() {
  const entries = new Set(['localhost', '127.0.0.1', '::1'])
  for (const list of Object.values(networkInterfaces())) {
    for (const iface of list ?? []) {
      if (iface.internal) continue
      entries.add(iface.address)
    }
  }
  return [...entries]
}

/**
 * Generate a self-signed ECDSA P-256 server certificate.
 * @param {{ cn?: string, days?: number, altNames?: string[] }} [options]
 * @returns {{ certPem: string, keyPem: string, certDer: Buffer, notBefore: Date, notAfter: Date, altNames: string[] }}
 */
export function generateSelfSignedCert(options = {}) {
  const cn = options.cn ?? 'dsh-lan-access'
  const days = options.days ?? 825
  const altNames = options.altNames ?? localSanEntries()

  const { publicKey, privateKey } = generateKeyPairSync('ec', {
    namedCurve: 'prime256v1',
  })

  const serial = randomBytes(8)
  serial[0] &= 0x7f // keep the serial positive

  const notBefore = new Date(Date.now() - 60 * 60 * 1000)
  const notAfter = new Date(notBefore.getTime() + days * 24 * 60 * 60 * 1000)

  const sanValues = altNames.map((entry) => {
    const ipv4 = /^(\d{1,3}\.){3}\d{1,3}$/.test(entry)
    const ipv6 = entry.includes(':')
    if (ipv4) {
      const bytes = entry.split('.').map((n) => Number.parseInt(n, 10))
      return tlv(0x87, Buffer.from(bytes))
    }
    if (ipv6) {
      // Expand then pack; reuse a minimal expansion to keep this module
      // self-contained (full expansion logic lives in cidr.js).
      const packed = packIpv6(entry)
      return tlv(0x87, packed)
    }
    // dNSName is an IA5String — the tag 0x82 must wrap the raw text bytes,
    // not a pre-encoded TLV.
    return tlv(0x82, Buffer.from(entry, 'ascii'))
  })

  const extensions = seq([
    extension('2.5.29.19', true, seq([])), // basicConstraints: CA = false
    extension('2.5.29.15', true, bitString([0xa0])), // digitalSignature | keyEncipherment
    extension('2.5.29.17', false, seq(sanValues)), // subjectAltName
    extension('2.5.29.37', false, seq([oid('1.3.6.1.5.5.7.3.1')])), // serverAuth
  ])

  const spkiDer = publicKey.export({ type: 'spki', format: 'der' })

  const tbs = seq([
    explicit(0, integer([0x02])), // version v3
    integer(serial),
    ECDSA_SHA256_ALG,
    name(cn),
    seq([utcTime(notBefore), utcTime(notAfter)]),
    name(cn),
    spkiDer,
    explicit(3, extensions),
  ])

  const signature = sign('sha256', tbs, privateKey) // DER ECDSA-Sig-Value
  const certDer = seq([tbs, ECDSA_SHA256_ALG, bitString(signature)])
  const keyPem = privateKey.export({ type: 'pkcs8', format: 'pem' })

  return {
    certPem: pem('CERTIFICATE', certDer),
    keyPem,
    certDer,
    notBefore,
    notAfter,
    altNames,
  }
}

/** Minimal IPv6 → 16 bytes packing (for subjectAltName values). */
function packIpv6(address) {
  let text = address.toLowerCase()
  const v4Tail = /^(.*:)(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(text)
  if (v4Tail !== null) {
    const octets = [v4Tail[2], v4Tail[3], v4Tail[4], v4Tail[5]].map((n) => Number.parseInt(n, 10))
    text = `${v4Tail[1]}${octets[0].toString(16).padStart(2, '0')}${octets[1].toString(16).padStart(2, '0')}:${octets[2].toString(16).padStart(2, '0')}${octets[3].toString(16).padStart(2, '0')}`
  }
  const halves = text.split('::')
  const head = halves[0] === '' ? [] : halves[0].split(':')
  let groups
  if (halves.length === 2) {
    const tail = halves[1] === '' ? [] : halves[1].split(':')
    const missing = 8 - head.length - tail.length
    groups = [...head, ...Array.from({ length: missing }, () => '0'), ...tail]
  } else {
    groups = head
  }
  const out = Buffer.alloc(16)
  groups.forEach((group, i) => {
    const value = Number.parseInt(group, 16)
    out[i * 2] = value >> 8
    out[i * 2 + 1] = value & 0xff
  })
  return out
}
