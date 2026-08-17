// bundle.test.js — pins the `dsh.bundle` composition contract.
//
// A bundle package declares `dsh.bundle.patch`; its patch file is applied as
// a profile layer. This test replicates the deployment's patch semantics
// (dsh-app-boot `applyEntryPatches`: id-targeted per-key merge, `config`
// wholesale replacement, `insert` lists) so the bundle contract is verified
// here rather than only at boot time.

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import http from 'node:http'
import { load as loadYaml } from 'js-yaml'
import { hashPassword } from '../lib/scrypt.js'
import { ensureSelfLink, PROJECT_ROOT } from './helpers.mjs'

const BUNDLE_PATCH = join(PROJECT_ROOT, 'cordis.patch.yml')

/**
 * Replica of dsh-app-boot's `applyEntryPatches` semantics.
 * @param {object[]} data initial entry list
 * @param {object[]} patches patch entries, in order
 * @param {(msg: string, ...args: unknown[]) => void} [warn]
 * @returns {object[]} a detached, patched entry list
 */
function applyEntryPatches(data, patches, warn = () => {}) {
  const out = structuredClone(data)
  const entryMap = new Map()
  const buildMap = (entries) => {
    for (const entry of entries) {
      if (entry.id) entryMap.set(entry.id, entry)
      if (entry.group && Array.isArray(entry.config)) buildMap(entry.config)
    }
  }
  buildMap(out)
  for (const patch of patches) {
    const { id, insert, name, ...overrides } = patch
    if (insert) {
      if (id) {
        const target = entryMap.get(id)
        if (!target) {
          warn('patch insert: entry %C not found', id)
          continue
        }
        if (!target.group) {
          warn('patch insert: entry %C is not a group', id)
          continue
        }
        if (!Array.isArray(target.config)) target.config = []
        target.config.push(...insert)
      } else {
        out.push(...insert)
      }
      buildMap(insert)
      continue
    }
    if (!id) {
      warn('patch: id is required for non-insert patches')
      continue
    }
    const target = entryMap.get(id)
    if (!target) {
      warn('patch: entry %C not found', id)
      continue
    }
    if (name && name !== target.name) {
      warn('patch: name mismatch for %C (expected %C, got %C), skipping', id, target.name, name)
      continue
    }
    for (const [key, value] of Object.entries(overrides)) {
      if (key === 'id') continue
      target[key] = value
    }
  }
  return out
}

function bundlePatch() {
  return loadYaml(readFileSync(BUNDLE_PATCH, 'utf8'))
}

test('bundle manifest declares dsh.bundle.patch', () => {
  const manifest = JSON.parse(readFileSync(join(PROJECT_ROOT, 'package.json'), 'utf8'))
  assert.equal(manifest.dsh?.bundle?.patch, './cordis.patch.yml')
})

test('bundle patch is valid YAML: lan-access row (fail-closed) + pinned browse picker', () => {
  const patch = bundlePatch()
  const inserts = patch.flatMap((p) => p.insert ?? [])
  const overrides = patch.filter((p) => p.insert === undefined)

  // The lan-access row: inserted, identity only, not disabled, no config.
  const lanRow = inserts.find((r) => r.id === 'lan-access')
  assert.ok(lanRow, 'lan-access row must be inserted')
  assert.equal(lanRow.name, 'dsh-full-lan-access')
  assert.equal(lanRow.config, undefined, 'bundle row ships without config → fail closed until configured')
  assert.equal(lanRow.disabled, undefined, 'bundle row must not be disabled')

  // The adaptive picker is disabled so the native OS chooser never mounts.
  const picker = overrides.find((p) => p.id === 'directory-picker')
  assert.ok(picker, 'directory-picker must be patched')
  assert.equal(picker.disabled, true, 'the native/adaptive picker must be disabled')

  // The browser-based browse pair is composed directly (the documented way
  // to pin the interaction).
  const browseHost = inserts.find((r) => r.id === 'directory-picker-browse')
  const browseUi = inserts.find((r) => r.id === 'ui-directory-picker-browse')
  assert.equal(browseHost?.name, '@deepseek-ai/dsh-host-directory-picker-browse')
  assert.equal(browseUi?.name, '@deepseek-ai/dsh-client-ui-directory-picker-browse')
})

test('a bare id-targeted patch over an empty list is skipped with a warning (doc contract)', () => {
  const warnings = []
  const composed = applyEntryPatches([], [{ id: 'lan-access', name: 'dsh-full-lan-access', config: {} }], (m, ...a) => warnings.push(String(m)))
  assert.equal(composed.length, 0)
  assert.ok(warnings.some((w) => w.includes('not found')), `expected a skip warning, got ${warnings.join('; ')}`)
})

test('user config override replaces the bundle row config while keeping its identity', () => {
  const composed = applyEntryPatches([], bundlePatch())
  const final = applyEntryPatches(composed, [
    { id: 'lan-access', config: { security: { passwordHash: 'scrypt$1$1$1$ab$cd' } } },
  ])
  const [row] = final
  assert.equal(row.id, 'lan-access')
  assert.equal(row.name, 'dsh-full-lan-access', 'name must survive the override')
  assert.deepEqual(row.config, { security: { passwordHash: 'scrypt$1$1$1$ab$cd' } }, 'config replaced wholesale')
  assert.equal(row.disabled, undefined, 'no disabled leakage into the override')
})

test('the bundle row mounts fail-closed without config, and starts with the user override', async () => {
  ensureSelfLink()
  const upstream = await startFakeUpstream()
  const { default: Loader } = await import('@deepseek-ai/cordis-plugin-loader')
  const { Context } = await import('@deepseek-ai/cordis')
  const baseUrl = PROJECT_ROOT

  // 1) Bundle-composed row (id + name only) must fail loudly at startup.
  const ctx1 = new Context()
  try {
    await ctx1.plugin(Loader, { baseUrl })
    await assert.rejects(
      ctx1.loader.create({ name: 'dsh-full-lan-access' }),
      /passwordHash is not set/,
      'unconfigured bundle row must fail closed',
    )
  } finally {
    await ctx1.fiber.dispose()
  }

  // 2) The same row plus the user's config override starts and proxies.
  const hash = hashPassword('bundle-test-password')
  const ctx2 = new Context()
  let entryId
  try {
    await ctx2.plugin(Loader, { baseUrl })
    entryId = await ctx2.loader.create({
      name: 'dsh-full-lan-access',
      config: {
        enabled: true,
        listen: { host: '127.0.0.1', port: 0 },
        upstream: { host: '127.0.0.1', port: upstream.port },
        security: { passwordHash: hash },
      },
    })
    await ctx2.loader.await()
    const service = ctx2.get('lanAccess')
    assert.ok(service, 'configured bundle row must expose the lanAccess service')
    const res = await new Promise((resolve, reject) => {
      http.get({ host: '127.0.0.1', port: service.status().listen.port, path: '/' }, (r) => {
        let data = ''
        r.on('data', (c) => { data += c })
        r.on('end', () => resolve({ status: r.statusCode, body: data }))
      }).on('error', reject)
    })
    assert.equal(res.status, 200)
    assert.equal(res.body, 'bundle-upstream-ok')
  } finally {
    if (entryId !== undefined) await ctx2.loader.remove(entryId)
    await ctx2.fiber.dispose()
    upstream.server.closeAllConnections()
    upstream.server.close()
  }
})

function startFakeUpstream() {
  return new Promise((resolve) => {
    const server = http.createServer((req, res) => {
      res.writeHead(200, { 'content-type': 'text/plain' })
      res.end('bundle-upstream-ok')
    })
    server.listen(0, '127.0.0.1', () => resolve({ server, port: server.address().port }))
  })
}
