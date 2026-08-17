// scrypt.test.js — password hashing format and verification.

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { scryptSync } from 'node:crypto'
import { hashPassword, parseHash, verifyPassword } from '../lib/scrypt.js'

test('hashPassword produces the scrypt$N$r$p$salt$hash format', () => {
  const hash = hashPassword('hunter2')
  assert.match(hash, /^scrypt\$16384\$8\$1\$[A-Za-z0-9+/=]+\$[A-Za-z0-9+/=]+$/)
  const parsed = parseHash(hash)
  assert.equal(parsed.N, 16384)
  assert.equal(parsed.r, 8)
  assert.equal(parsed.p, 1)
  assert.equal(parsed.hash.length, 32)
})

test('verifyPassword round-trips and rejects wrong passwords', () => {
  const hash = hashPassword('correct horse battery staple')
  assert.equal(verifyPassword('correct horse battery staple', hash), true)
  assert.equal(verifyPassword('wrong', hash), false)
  assert.equal(verifyPassword('', hash), false)
})

test('hashes are salted (same password, different hashes)', () => {
  const a = hashPassword('same')
  const b = hashPassword('same')
  assert.notEqual(a, b)
  assert.equal(verifyPassword('same', a), true)
  assert.equal(verifyPassword('same', b), true)
})

test('custom parameters are honored', () => {
  const hash = hashPassword('pw', { N: 32768, r: 8, p: 2 })
  const parsed = parseHash(hash)
  assert.equal(parsed.N, 32768)
  assert.equal(parsed.p, 2)
  assert.equal(verifyPassword('pw', hash), true)
})

test('malformed hashes never throw and always fail', () => {
  assert.equal(verifyPassword('pw', 'not-a-hash'), false)
  assert.equal(verifyPassword('pw', 'scrypt$1$1$1$ab$cd'), false)
  assert.equal(verifyPassword('pw', 'scrypt$16384$8$1$!!$!!'), false)
  assert.equal(verifyPassword('pw', ''), false)
  assert.equal(verifyPassword('pw', null), false)
  assert.equal(parseHash('scrypt$abc$8$1$x$y'), null)
  assert.equal(parseHash('md5$1$2$3$4$5'), null)
})

test('a hash with legacy shorter key length verifies against itself', () => {
  // The parser accepts whatever key length the hash declares.
  const salt = Buffer.alloc(16, 1)
  const derived = scryptSync('pw', salt, 16, { N: 16384, r: 8, p: 1 })
  const encoded = `scrypt$16384$8$1$${salt.toString('base64')}$${derived.toString('base64')}`
  assert.equal(verifyPassword('pw', encoded), true)
  assert.equal(verifyPassword('other', encoded), false)
})

test('hashPassword rejects non-string input', () => {
  assert.throws(() => hashPassword(42), TypeError)
})
