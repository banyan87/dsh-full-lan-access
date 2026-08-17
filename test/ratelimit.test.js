// ratelimit.test.js — sliding-window rate limiter behavior.

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createRateLimiter } from '../lib/ratelimit.js'

test('allows up to max hits per window', () => {
  let now = 0
  const limiter = createRateLimiter({ max: 3, windowMs: 1000, now: () => now })
  assert.equal(limiter.hit('a').allowed, true)
  assert.equal(limiter.hit('a').allowed, true)
  assert.equal(limiter.hit('a').allowed, true)
  const blocked = limiter.hit('a')
  assert.equal(blocked.allowed, false)
  assert.ok(blocked.retryAfterMs > 0)
  // different key unaffected
  assert.equal(limiter.hit('b').allowed, true)
})

test('window slides: old hits expire', () => {
  let now = 0
  const limiter = createRateLimiter({ max: 2, windowMs: 1000, now: () => now })
  limiter.hit('a')
  now = 500
  limiter.hit('a')
  assert.equal(limiter.hit('a').allowed, false)
  now = 1501 // both earlier hits (t=0 and t=500) are now outside the window
  assert.equal(limiter.hit('a').allowed, true)
})

test('peek does not record hits', () => {
  let now = 0
  const limiter = createRateLimiter({ max: 1, windowMs: 1000, now: () => now })
  assert.equal(limiter.peek('x').allowed, true)
  limiter.hit('x')
  assert.equal(limiter.peek('x').allowed, false)
  assert.equal(limiter.peek('y').allowed, true)
})

test('reset clears a key', () => {
  let now = 0
  const limiter = createRateLimiter({ max: 1, windowMs: 1000, now: () => now })
  limiter.hit('k')
  assert.equal(limiter.hit('k').allowed, false)
  limiter.reset('k')
  assert.equal(limiter.hit('k').allowed, true)
})

test('size reflects tracked keys', () => {
  const limiter = createRateLimiter({ max: 5, windowMs: 1000 })
  limiter.hit('a')
  limiter.hit('b')
  assert.equal(limiter.size(), 2)
})
