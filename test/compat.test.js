// compat.test.js — browser-compatibility shim helpers.

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { RANDOM_UUID_POLYFILL, injectIntoHtml, isInjectableHtml } from '../lib/compat.js'

test('the polyfill is a guarded script that defines crypto.randomUUID', () => {
  assert.match(RANDOM_UUID_POLYFILL, /<script>/)
  assert.match(RANDOM_UUID_POLYFILL, /randomUUID/)
  assert.match(RANDOM_UUID_POLYFILL, /getRandomValues/)
  assert.match(RANDOM_UUID_POLYFILL, /typeof c\.randomUUID === 'function'/, 'must no-op when already available')
})

test('injectIntoHtml inserts before </head>', () => {
  const html = '<!doctype html><html><head><title>x</title></head><body>hi</body></html>'
  const script = '<script>SHIM</script>'
  const out = injectIntoHtml(html, script)
  const at = out.indexOf(script)
  assert.ok(at !== -1)
  assert.equal(out.slice(at + script.length, at + script.length + '</head>'.length), '</head>')
  assert.equal(out.indexOf('</head>') - at, script.length)
})

test('injectIntoHtml falls back to before </body>, then appends', () => {
  const noHead = '<html><body>hi</body></html>'
  const script = 'X'
  const out = injectIntoHtml(noHead, script)
  const at = out.indexOf(script)
  assert.equal(out.slice(at + script.length, at + script.length + '</body>'.length), '</body>')
  const bare = 'plain text'
  assert.equal(injectIntoHtml(bare, 'Y'), bare + 'Y')
})

test('isInjectableHtml accepts text/html and rejects other types and encodings', () => {
  assert.equal(isInjectableHtml('text/html; charset=utf-8', undefined), true)
  assert.equal(isInjectableHtml('text/html', undefined), true)
  assert.equal(isInjectableHtml('application/json', undefined), false)
  assert.equal(isInjectableHtml('text/html', 'gzip'), false)
  assert.equal(isInjectableHtml(undefined, undefined), false)
})
