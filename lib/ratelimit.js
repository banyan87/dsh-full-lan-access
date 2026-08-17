// ratelimit.js — sliding-window per-key rate limiter.
//
// Used for login attempts (per client IP) and, optionally, for general
// per-IP request throttling. Keys are client IPs; the window slides with the
// oldest recorded hit, so bursts spread across a boundary are handled fairly.

/**
 * @param {{ max?: number, windowMs?: number, now?: () => number }} options
 */
export function createRateLimiter(options = {}) {
  const max = options.max ?? 5
  const windowMs = options.windowMs ?? 15 * 60 * 1000
  const now = options.now ?? Date.now
  /** @type {Map<string, number[]>} key → hit timestamps (ascending) */
  const buckets = new Map()

  function windowStart(key) {
    const cutoff = now() - windowMs
    const hits = buckets.get(key)
    if (hits === undefined) return
    while (hits.length > 0 && hits[0] <= cutoff) hits.shift()
    if (hits.length === 0) buckets.delete(key)
  }

  return {
    /**
     * Record one hit for a key.
     * @returns {{ allowed: boolean, count: number, retryAfterMs: number }}
     */
    hit(key) {
      windowStart(key)
      let hits = buckets.get(key)
      if (hits === undefined) {
        hits = []
        buckets.set(key, hits)
      }
      hits.push(now())
      if (hits.length > max) {
        // The oldest hit is older than the window start, so it has already
        // been pruned above; a count above max means the newest hit overflows.
        const retryAfterMs = hits[0] + windowMs - now()
        return { allowed: false, count: hits.length, retryAfterMs: Math.max(retryAfterMs, 0) }
      }
      return { allowed: true, count: hits.length, retryAfterMs: 0 }
    },

    /** Remaining allowance for a key without recording a hit. */
    peek(key) {
      windowStart(key)
      const hits = buckets.get(key) ?? []
      return { allowed: hits.length < max, count: hits.length, retryAfterMs: 0 }
    },

    reset(key) {
      buckets.delete(key)
    },

    /** Number of distinct keys currently tracked (stats only). */
    size() {
      return buckets.size
    },
  }
}
