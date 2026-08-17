// cidr.test.js — unit tests for the CIDR matcher and IP policy.

import { test } from 'node:test'
import assert from 'node:assert/strict'
import {
  buildIpPolicy,
  cidrContains,
  expandIpv6,
  isLoopback,
  normalizeIp,
  parseCidr,
} from '../lib/cidr.js'

test('normalizeIp strips IPv4-mapped forms and rejects garbage', () => {
  assert.equal(normalizeIp('::ffff:192.168.1.10'), '192.168.1.10')
  assert.equal(normalizeIp('::FFFF:10.0.0.1'), '10.0.0.1')
  assert.equal(normalizeIp('127.0.0.1'), '127.0.0.1')
  assert.equal(normalizeIp('2001:db8::1'), '2001:0db8:0000:0000:0000:0000:0000:0001')
  assert.equal(normalizeIp('not-an-ip'), null)
  assert.equal(normalizeIp(''), null)
  assert.equal(normalizeIp(null), null)
})

test('expandIpv6 handles :: compression and IPv4 tails', () => {
  assert.equal(expandIpv6('::1'), '0000:0000:0000:0000:0000:0000:0000:0001')
  assert.equal(expandIpv6('fe80::1'), 'fe80:0000:0000:0000:0000:0000:0000:0001')
  assert.equal(expandIpv6('2001:db8::1:2:3'), '2001:0db8:0000:0000:0000:0001:0002:0003')
  assert.equal(expandIpv6('::ffff:192.168.0.1'), '0000:0000:0000:0000:0000:ffff:c0a8:0001')
  assert.equal(expandIpv6('bad:'), null)
  assert.equal(expandIpv6('1:2:3:4:5:6:7:8:9'), null)
})

test('parseCidr validates families and prefix ranges', () => {
  const v4 = parseCidr('192.168.0.0/16')
  assert.equal(v4.family, 4)
  assert.equal(v4.prefix, 16)
  assert.equal(parseCidr('10.0.0.1').prefix, 32)
  assert.equal(parseCidr('2001:db8::/32').family, 6)
  assert.equal(parseCidr('::1').prefix, 128)
  assert.equal(parseCidr('any').prefix, 0)
  assert.equal(parseCidr('10.0.0.0/33'), null)
  assert.equal(parseCidr('2001:db8::/129'), null)
  assert.equal(parseCidr('not-a-cidr'), null)
  assert.equal(parseCidr('10.0.0.0/-1'), null)
})

test('cidrContains matches IPv4 and IPv6', () => {
  const lan = parseCidr('192.168.1.0/24')
  assert.equal(cidrContains(lan, '192.168.1.5'), true)
  assert.equal(cidrContains(lan, '192.168.2.5'), false)
  assert.equal(cidrContains(lan, '::ffff:192.168.1.5'), true)
  assert.equal(cidrContains(lan, '10.0.0.1'), false)
  assert.equal(cidrContains(lan, 'garbage'), false)

  const v6 = parseCidr('2001:db8::/32')
  assert.equal(cidrContains(v6, '2001:db8::1234'), true)
  assert.equal(cidrContains(v6, '2001:db9::1'), false)
})

test('buildIpPolicy: deny always wins; unknown outside lists', () => {
  const policy = buildIpPolicy({
    allow: ['10.0.0.0/8', '192.168.0.0/16'],
    deny: ['10.0.0.0/8'],
  })
  assert.equal(policy.decide('10.1.2.3'), 'deny')
  assert.equal(policy.decide('192.168.1.1'), 'allow')
  assert.equal(policy.decide('8.8.8.8'), 'unknown')
  assert.equal(policy.decide('::1'), 'unknown')
  assert.equal(policy.decide('::ffff:10.0.0.1'), 'deny')
  assert.equal(policy.decide('bad'), 'unknown')

  const anyPolicy = buildIpPolicy({ allow: ['any'], deny: [] })
  assert.equal(anyPolicy.decide('8.8.8.8'), 'allow')
  assert.equal(anyPolicy.decide('::1'), 'unknown') // 'any' covers v4 only
  assert.equal(anyPolicy.decide('::ffff:8.8.8.8'), 'allow')
})

test('buildIpPolicy throws on invalid CIDR entries', () => {
  assert.throws(() => buildIpPolicy({ allow: ['10.0.0.0/99'], deny: [] }), /invalid CIDR/)
  assert.throws(() => buildIpPolicy({ allow: ['nope'], deny: [] }), /invalid CIDR/)
})

test('isLoopback detects IPv4 loopback and ::1', () => {
  assert.equal(isLoopback('127.0.0.1'), true)
  assert.equal(isLoopback('127.8.9.10'), true)
  assert.equal(isLoopback('::1'), true)
  assert.equal(isLoopback('::ffff:127.0.0.1'), true)
  assert.equal(isLoopback('10.0.0.1'), false)
  assert.equal(isLoopback('2001:db8::1'), false)
  assert.equal(isLoopback('garbage'), false)
})
