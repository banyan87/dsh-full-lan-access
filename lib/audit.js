// audit.js — JSON-lines audit log.
//
// Every security-relevant event is emitted as one JSON object per line:
// timestamp, level, event name, and a small set of scalar fields. Logs go to
// the DSH logger and, when configured, to a file. No sensitive material
// (passwords, session tokens, hashes) is ever written.

import { appendFileSync } from 'node:fs'
import { dirname } from 'node:path'
import { mkdirSync } from 'node:fs'

const LEVELS = { error: 0, warn: 1, info: 2, debug: 3 }

/**
 * @param {{ level?: keyof typeof LEVELS | string, filePath?: string | null, sink?: (line: string) => void, now?: () => number }} options
 */
export function createAuditLog(options = {}) {
  const threshold = LEVELS[options.level] ?? LEVELS.info
  const filePath = options.filePath ?? null
  const sink = options.sink ?? ((line) => console.log(line))
  const now = options.now ?? Date.now

  let open = true
  if (filePath !== null) {
    try {
      mkdirSync(dirname(filePath), { recursive: true })
    } catch {
      // The audit file is best-effort; a broken path only disables file logs.
    }
  }

  function write(level, event, fields = {}) {
    if (!open) return
    if (LEVELS[level] === undefined || LEVELS[level] > threshold) return
    const line = JSON.stringify({
      ts: new Date(now()).toISOString(),
      level,
      event,
      ...fields,
    })
    try {
      sink(line)
      if (filePath !== null) appendFileSync(filePath, `${line}\n`, 'utf8')
    } catch {
      // Logging must never take the gateway down.
    }
  }

  return {
    error: (event, fields) => write('error', event, fields),
    warn: (event, fields) => write('warn', event, fields),
    info: (event, fields) => write('info', event, fields),
    debug: (event, fields) => write('debug', event, fields),
    close() {
      open = false
    },
  }
}
