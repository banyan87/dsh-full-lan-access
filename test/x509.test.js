// x509.test.js — self-signed certificate generation must produce a real,
// self-issued ECDSA server certificate that Node's own X509Certificate can
// parse and verify.

import { test } from 'node:test'
import assert from 'node:assert/strict'
import tls from 'node:tls'
import { X509Certificate, createPrivateKey } from 'node:crypto'
import { generateSelfSignedCert, localSanEntries } from '../lib/x509.js'

test('generates a parseable, cryptographically self-consistent certificate', () => {
  const { certPem, notBefore, notAfter, altNames } = generateSelfSignedCert({
    cn: 'test-lan-gate',
    days: 30,
    altNames: ['localhost', '127.0.0.1', '::1'],
  })

  const cert = new X509Certificate(certPem)
  assert.equal(cert.subject, 'CN=test-lan-gate')
  assert.equal(cert.issuer, 'CN=test-lan-gate')
  assert.equal(cert.verify(cert.publicKey), true, 'signature must verify with its own key')
  assert.ok(cert.validFrom !== '')
  assert.ok(cert.validTo !== '')
  assert.ok(cert.subjectAltName.includes('DNS:localhost'))
  assert.ok(cert.subjectAltName.includes('IP Address:127.0.0.1'))
  assert.ok(notBefore < notAfter)
})

test('the certificate completes a full TLS handshake as a trust root', async () => {
  const { certPem, keyPem } = generateSelfSignedCert({
    cn: 'tls-check',
    days: 30,
    altNames: ['localhost', '127.0.0.1'],
  })

  const server = tls.createServer({ cert: certPem, key: keyPem }, (socket) => {
    socket.end('tls-ok')
  })
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve))
  try {
    const port = server.address().port
    const result = await new Promise((resolve) => {
      const socket = tls.connect({
        host: '127.0.0.1',
        port,
        servername: 'localhost',
        ca: [certPem], // trust the self-signed certificate as the root
        rejectUnauthorized: true,
      }, () => {
        socket.on('data', (data) => {
          resolve({ authorized: socket.authorized, error: socket.authorizationError, data: data.toString() })
        })
      })
      socket.on('error', (err) => {
        resolve({ authorized: false, error: String(err), data: null })
      })
    })
    assert.equal(result.authorized, true, `handshake must be authorized (${result.error})`)
    assert.equal(result.data, 'tls-ok')
  } finally {
    server.close()
  }
})

test('private key PEM round-trips', () => {
  const { keyPem } = generateSelfSignedCert({ altNames: ['localhost'] })
  assert.match(keyPem, /-----BEGIN PRIVATE KEY-----/)
  // Node can load it back.
  assert.doesNotThrow(() => createPrivateKey(keyPem))
})

test('localSanEntries always includes localhost and loopback', () => {
  const entries = localSanEntries()
  assert.ok(entries.includes('localhost'))
  assert.ok(entries.includes('127.0.0.1'))
  assert.ok(entries.includes('::1'))
})
