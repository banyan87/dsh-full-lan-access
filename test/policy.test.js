// policy.test.js — pure request-policy helpers.

import { test } from 'node:test'
import assert from 'node:assert/strict'
import {
  authRequiredFor,
  clientIpOf,
  forwardableHeaders,
  parseCookies,
  presentProxyHeaders,
  requestKind,
  wantsHtml,
} from '../lib/policy.js'

function fakeReq({ remoteAddress = '192.168.1.5', headers = {}, url = '/' } = {}) {
  return {
    socket: { remoteAddress },
    headers,
    url,
  }
}

test('clientIpOf normalizes the socket address', () => {
  assert.deepEqual(clientIpOf(fakeReq({ remoteAddress: '::ffff:10.0.0.9' })), {
    ip: '10.0.0.9',
    rawIp: '::ffff:10.0.0.9',
  })
  assert.equal(clientIpOf(fakeReq({ remoteAddress: '10.1.2.3' })).ip, '10.1.2.3')
  assert.equal(clientIpOf({ socket: {}, headers: {} }).ip, null)
})

test('presentProxyHeaders detects spoofable headers', () => {
  assert.deepEqual(presentProxyHeaders(fakeReq()), [])
  const req = fakeReq({
    headers: { 'x-forwarded-for': '1.2.3.4', 'x-real-ip': '5.6.7.8', accept: 'text/html' },
  })
  assert.deepEqual(presentProxyHeaders(req), ['x-forwarded-for', 'x-real-ip'])
})

test('authRequiredFor honors loopback bypass and the master switch', () => {
  const base = { requireAuth: true, loopbackBypassAuth: true }
  assert.equal(authRequiredFor({ ...base, ip: '127.0.0.1' }), false)
  assert.equal(authRequiredFor({ ...base, ip: '::1' }), false)
  assert.equal(authRequiredFor({ ...base, ip: '192.168.1.5' }), true)
  assert.equal(authRequiredFor({ ...base, ip: null }), true)
  assert.equal(authRequiredFor({ ...base, ip: '10.0.0.1', loopbackBypassAuth: false }), true)
  assert.equal(authRequiredFor({ ...base, ip: '10.0.0.1', requireAuth: false }), false)
})

test('parseCookies handles simple, quoted, and empty values', () => {
  assert.deepEqual(parseCookies('a=1; b=two; c="three"'), { a: '1', b: 'two', c: 'three' })
  assert.deepEqual(parseCookies(''), {})
  assert.deepEqual(parseCookies(undefined), {})
  assert.deepEqual(parseCookies('justaname'), {})
})

test('requestKind distinguishes websocket upgrades', () => {
  assert.equal(requestKind(fakeReq()), 'http')
  assert.equal(requestKind(fakeReq({ headers: { upgrade: 'websocket' } })), 'websocket')
  assert.equal(requestKind(fakeReq({ headers: { upgrade: 'WebSocket' } })), 'websocket')
})

test('wantsHtml follows the Accept header', () => {
  assert.equal(wantsHtml(fakeReq({ headers: { accept: 'text/html,application/xhtml+xml' } })), true)
  assert.equal(wantsHtml(fakeReq({ headers: { accept: 'application/json' } })), false)
  assert.equal(wantsHtml(fakeReq({ headers: {} })), true)
})

test('forwardableHeaders strips hop-by-hop, host, and gateway cookies', () => {
  const req = fakeReq({
    headers: {
      host: '192.168.1.5:3081',
      connection: 'keep-alive',
      'transfer-encoding': 'chunked',
      'user-agent': 'test-agent',
      cookie: 'dsh_lan_session=abc; dsh_lan_session_csrf=xyz; other=kept',
      accept: '*/*',
    },
  })
  const out = forwardableHeaders(req, 'dsh_lan_session')
  assert.equal(out.host, undefined)
  assert.equal(out.connection, undefined)
  assert.equal(out['transfer-encoding'], undefined)
  assert.equal(out['user-agent'], 'test-agent')
  assert.equal(out.cookie, 'other=kept')
})
