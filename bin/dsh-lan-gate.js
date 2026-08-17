#!/usr/bin/env node
// dsh-lan-gate — operator CLI for dsh-full-lan-access.
//
// Commands:
//   dsh-lan-gate hash-password [password]   hash a password (prompts when omitted)
//   dsh-lan-gate verify <password> <hash>   check a password against a hash
//   dsh-lan-gate cidr <ip> <cidr...>        test whether an IP matches any CIDR
//   dsh-lan-gate check-config <file.json>   validate a config file
//
// The tool has no runtime dependencies beyond Node builtins, so it works
// even before the plugin is installed into a DSH profile.

import { readFileSync } from 'node:fs'
import { createInterface } from 'node:readline'
import { hashPassword, verifyPassword } from '../lib/scrypt.js'
import { cidrContains, normalizeIp, parseCidr } from '../lib/cidr.js'
import { resolveConfig } from '../lib/config.js'

const USAGE = `dsh-lan-gate — operator CLI for dsh-full-lan-access

Usage:
  dsh-lan-gate hash-password [password]   hash a password (prompts when omitted)
  dsh-lan-gate verify <password> <hash>   check a password against a hash
  dsh-lan-gate cidr <ip> <cidr...>        test whether an IP matches any CIDR
  dsh-lan-gate check-config <file.json>   validate a config file
  dsh-lan-gate help                       show this help
`

function fail(message) {
  console.error(`error: ${message}`)
  process.exitCode = 1
}

async function promptSecret(prompt) {
  return new Promise((resolve) => {
    const rl = createInterface({ input: process.stdin, output: process.stdout, terminal: true })
    process.stdout.write(prompt)
    const onData = (char) => {
      process.stdout.write('\x1b[2K\r')
    }
    process.stdin.on('data', onData)
    rl.question('', (answer) => {
      process.stdin.removeListener('data', onData)
      rl.close()
      process.stdout.write('\n')
      resolve(answer)
    })
  })
}

async function main(argv) {
  const [command, ...rest] = argv

  if (command === 'hash-password') {
    const password = rest[0] ?? await promptSecret('Password: ')
    if (password.length === 0) {
      fail('password must not be empty')
      return
    }
    console.log(hashPassword(password))
    return
  }

  if (command === 'verify') {
    const [password, hash] = rest
    if (password === undefined || hash === undefined) {
      fail('usage: dsh-lan-gate verify <password> <hash>')
      return
    }
    console.log(verifyPassword(password, hash) ? 'ok: password matches' : 'fail: password does not match')
    process.exitCode = verifyPassword(password, hash) ? 0 : 1
    return
  }

  if (command === 'cidr') {
    const [ip, ...cidrs] = rest
    if (ip === undefined || cidrs.length === 0) {
      fail('usage: dsh-lan-gate cidr <ip> <cidr...>')
      return
    }
    const normalized = normalizeIp(ip)
    if (normalized === null) {
      fail(`"${ip}" is not a valid IP address`)
      return
    }
    console.log(`normalized: ${normalized}`)
    for (const cidrText of cidrs) {
      const parsed = parseCidr(cidrText)
      if (parsed === null) {
        console.log(`${cidrText}: invalid`)
      } else {
        console.log(`${cidrText}: ${cidrContains(parsed, normalized) ? 'match' : 'no match'}`)
      }
    }
    return
  }

  if (command === 'check-config') {
    const [file] = rest
    if (file === undefined) {
      fail('usage: dsh-lan-gate check-config <file.json>')
      return
    }
    let raw
    try {
      raw = readFileSync(file, 'utf8')
    } catch (err) {
      fail(`cannot read ${file}: ${err.message}`)
      return
    }
    try {
      const parsed = JSON.parse(raw)
      const resolved = resolveConfig(parsed)
      console.log('ok: config is valid')
      console.log(`    listen:   ${resolved.listen.host}:${resolved.listen.port}`)
      console.log(`    upstream: ${resolved.upstream.protocol}://${resolved.upstream.host}:${resolved.upstream.port}`)
      console.log(`    auth:     ${resolved.security.requireAuth ? 'required' : 'off'}`)
      console.log(`    tls:      ${resolved.tls.enabled ? 'enabled' : 'off'}`)
      console.log(`    allow:    ${resolved.security.allowCidrs.join(', ')}`)
    } catch (err) {
      fail(`invalid config: ${err.message}`)
    }
    return
  }

  console.log(USAGE)
}

main(process.argv.slice(2))
