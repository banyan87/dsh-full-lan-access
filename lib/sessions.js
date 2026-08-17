// sessions.js — authenticated LAN-gateway session store.
//
// Tokens are 32 random bytes (hex). The store never persists the token
// itself: it persists the SHA-256 digest of the token plus the expiry, so a
// leaked state file cannot be replayed as a session. Because verification
// re-hashes the presented token, sessions survive a gateway restart.

import { createHash, randomBytes, timingSafeEqual } from 'node:crypto'
import { mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs'
import { dirname } from 'node:path'

function digest(token) {
  return createHash('sha256').update(token, 'utf8').digest('hex')
}

/**
 * @param {{ ttlMs?: number, maxSessions?: number, filePath?: string | null, now?: () => number }} options
 */
export function createSessionStore(options = {}) {
  const ttlMs = options.ttlMs ?? 7 * 24 * 60 * 60 * 1000
  const maxSessions = options.maxSessions ?? 64
  const filePath = options.filePath ?? null
  const now = options.now ?? Date.now

  /** @type {Map<string, number>} id (sha256 of token) → expiry ms */
  const sessions = new Map()

  function prune() {
    const cutoff = now()
    for (const [id, exp] of sessions) {
      if (exp <= cutoff) sessions.delete(id)
    }
  }

  function persist() {
    if (filePath === null) return
    const payload = JSON.stringify({
      sessions: [...sessions.entries()].map(([id, exp]) => ({ id, exp })),
    })
    mkdirSync(dirname(filePath), { recursive: true })
    const tmp = `${filePath}.tmp`
    writeFileSync(tmp, payload, 'utf8')
    renameSync(tmp, filePath)
  }

  function load() {
    if (filePath === null) return
    let raw
    try {
      raw = readFileSync(filePath, 'utf8')
    } catch {
      return
    }
    try {
      const parsed = JSON.parse(raw)
      if (!Array.isArray(parsed.sessions)) return
      for (const entry of parsed.sessions) {
        if (typeof entry?.id === 'string' && typeof entry?.exp === 'number') {
          sessions.set(entry.id, entry.exp)
        }
      }
      prune()
    } catch {
      // A corrupt state file is treated as no sessions (fail closed).
    }
  }

  load()

  return {
    /** Issue a new session; returns the token the client must keep. */
    issue() {
      prune()
      while (sessions.size >= maxSessions) {
        // Evict the oldest session.
        let oldestId = null
        let oldestExp = Number.POSITIVE_INFINITY
        for (const [id, exp] of sessions) {
          if (exp < oldestExp) {
            oldestExp = exp
            oldestId = id
          }
        }
        if (oldestId === null) break
        sessions.delete(oldestId)
      }
      const token = randomBytes(32).toString('hex')
      const id = digest(token)
      sessions.set(id, now() + ttlMs)
      persist()
      return { token, id, exp: sessions.get(id) }
    },

    /**
     * Validate a token. Returns the session record or null. Constant-time
     * lookup is not required (the id is a hash), but the record is compared
     * only by key equality on a 256-bit digest.
     */
    verify(token) {
      if (typeof token !== 'string' || token.length === 0) return null
      const id = digest(token)
      const exp = sessions.get(id)
      if (exp === undefined) return null
      if (exp <= now()) {
        sessions.delete(id)
        persist()
        return null
      }
      return { id, exp }
    },

    revoke(token) {
      if (typeof token !== 'string') return false
      const id = digest(token)
      const existed = sessions.delete(id)
      if (existed) persist()
      return existed
    },

    revokeById(id) {
      if (typeof id !== 'string') return false
      const existed = sessions.delete(id)
      if (existed) persist()
      return existed
    },

    list() {
      prune()
      return [...sessions.entries()]
        .map(([id, exp]) => ({ id, exp }))
        .sort((a, b) => a.exp - b.exp)
    },

    /** @returns {number} live session count (after pruning) */
    count() {
      prune()
      return sessions.size
    },
  }
}

/** Constant-time token comparison helper (defense in depth). */
export function tokensEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false
  const ab = Buffer.from(a, 'utf8')
  const bb = Buffer.from(b, 'utf8')
  return ab.length === bb.length && timingSafeEqual(ab, bb)
}
