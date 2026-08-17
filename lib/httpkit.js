// httpkit.js — tiny shared HTTP response helpers used by the plugin entry
// and the gateway. Kept separate from server.js so index.js can serve the
// local status route without pulling in the whole pipeline.

/**
 * @param {import('node:http').ServerResponse} res
 * @param {number} status
 * @param {unknown} obj
 */
export function sendJson(res, status, obj) {
  if (res.headersSent) {
    res.destroy()
    return
  }
  res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'cache-control': 'no-store',
  })
  res.end(JSON.stringify(obj))
}
