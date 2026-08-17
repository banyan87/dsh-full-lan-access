// sessions.test.js — session store: issue, verify, expiry, eviction, persistence.

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, rmSync, readFileSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { createSessionStore, tokensEqual } from '../lib/sessions.js'

function tempDir() {
  return mkdtempSync(join(tmpdir(), 'lan-access-test-'))
}

test('issue/verify round-trip and unknown tokens fail', () => {
  const store = createSessionStore({ now: () => 1_000_000 })
  const { token } = store.issue()
  assert.ok(store.verify(token))
  assert.equal(store.verify('deadbeef'), null)
  assert.equal(store.verify(''), null)
  assert.equal(store.verify(null), null)
  assert.equal(store.count(), 1)
})

test('expired sessions are rejected and pruned', () => {
  let now = 1_000_000
  const store = createSessionStore({ ttlMs: 1000, now: () => now })
  const { token } = store.issue()
  assert.ok(store.verify(token))
  now = 2_000_001
  assert.equal(store.verify(token), null)
  assert.equal(store.count(), 0)
})

test('revoke removes sessions', () => {
  const store = createSessionStore()
  const { token } = store.issue()
  assert.equal(store.revoke(token), true)
  assert.equal(store.verify(token), null)
  assert.equal(store.revoke(token), false)
})

test('maxSessions evicts the oldest session', () => {
  let now = 1_000_000
  const store = createSessionStore({ maxSessions: 2, now: () => now })
  const first = store.issue()
  now += 100
  const second = store.issue()
  now += 100
  const third = store.issue()
  assert.equal(store.verify(first.token), null)
  assert.ok(store.verify(second.token))
  assert.ok(store.verify(third.token))
  assert.equal(store.count(), 2)
})

test('sessions persist to disk and survive store recreation (token never stored)', () => {
  const dir = tempDir()
  try {
    const file = join(dir, 'sessions.json')
    const store = createSessionStore({ filePath: file, ttlMs: 60_000 })
    const { token, id } = store.issue()
    assert.equal(store.count(), 1)

    const raw = readFileSync(file, 'utf8')
    assert.ok(!raw.includes(token), 'token must not be persisted')
    const parsed = JSON.parse(raw)
    assert.equal(parsed.sessions.length, 1)
    assert.equal(parsed.sessions[0].id, id)

    const reloaded = createSessionStore({ filePath: file, ttlMs: 60_000 })
    assert.ok(reloaded.verify(token), 'token verifies after reload')
    assert.equal(reloaded.count(), 1)
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})

test('a corrupt state file fails closed', () => {
  const dir = tempDir()
  try {
    const file = join(dir, 'sessions.json')
    writeFileSync(file, '{ not json', 'utf8')
    const store = createSessionStore({ filePath: file })
    assert.equal(store.count(), 0)
    const { token } = store.issue()
    assert.ok(store.verify(token))
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})

test('tokensEqual is constant-time-ish and rejects mismatches', () => {
  assert.equal(tokensEqual('abc', 'abc'), true)
  assert.equal(tokensEqual('abc', 'abd'), false)
  assert.equal(tokensEqual('abc', 'ab'), false)
  assert.equal(tokensEqual(null, null), false)
})
