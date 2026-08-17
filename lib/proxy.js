// proxy.js — streaming HTTP + WebSocket reverse proxy to the DSH web server.
//
// Bodies are streamed (never buffered) except for injectable HTML pages,
// headers are sanitized via policy.forwardableHeaders (gateway cookies
// stripped, Origin rewritten to the upstream authority so DSH's /api trust
// fence passes), and WebSocket upgrades are tunneled over a raw TCP
// connection after authentication has already been enforced by the gateway
// request pipeline.

import http from 'node:http'
import https from 'node:https'
import net from 'node:net'
import { forwardableHeaders } from './policy.js'
import { injectIntoHtml, isInjectableHtml } from './compat.js'

/** Upper bound for buffered HTML pages (the DSH index is ~12 KB). */
const HTML_BUFFER_CAP = 512 * 1024

/**
 * @param {{ target: { protocol?: 'http' | 'https', host: string, port: number }, timeoutMs?: number, sessionCookieName?: string, audit?: any, rejectUnauthorized?: boolean, originAuthority?: string | null, htmlInjection?: { script: string } | null }} options
 */
export function createProxy(options) {
  const protocol = options.target.protocol ?? 'http'
  const targetHost = options.target.host
  const targetPort = options.target.port
  const timeoutMs = options.timeoutMs ?? 30_000
  const cookieName = options.sessionCookieName ?? 'dsh_lan_session'
  const audit = options.audit
  const rejectUnauthorized = options.rejectUnauthorized ?? false
  const originAuthority = options.originAuthority ?? null
  const htmlInjection = options.htmlInjection ?? null

  const upgradeSockets = new Set()

  const transport = protocol === 'https' ? https : http
  const targetAuthority = `${targetHost}:${targetPort}`

  function requestOptions(req) {
    return {
      protocol: `${protocol}:`,
      hostname: targetHost,
      port: targetPort,
      method: req.method,
      path: req.url,
      headers: {
        ...forwardableHeaders(req, cookieName, { originAuthority }),
        host: targetAuthority,
      },
      agent: false,
      rejectUnauthorized,
    }
  }

  /**
   * Proxy one HTTP request. Resolves when the response has been handed off.
   * @param {import('node:http').IncomingMessage} req
   * @param {import('node:http').ServerResponse} res
   * @returns {Promise<void>}
   */
  function proxyHttp(req, res) {
    return new Promise((resolve) => {
      const proxyReq = transport.request(requestOptions(req), (proxyRes) => {
        const statusCode = proxyRes.statusCode ?? 502
        const headers = {}
        let injectHtml = false
        if (
          htmlInjection !== null
          && isInjectableHtml(proxyRes.headers['content-type'], proxyRes.headers['content-encoding'])
        ) {
          injectHtml = true
          // The injected script changes the body size; let the transfer
          // encoding carry the new length.
          delete headers['content-length']
        }
        for (const [name, value] of Object.entries(proxyRes.headers)) {
          if (name === 'connection' || name === 'keep-alive' || name === 'transfer-encoding') {
            continue
          }
          if (injectHtml && name === 'content-length') continue
          headers[name] = String(value)
        }
        try {
          res.writeHead(statusCode, headers)
        } catch {
          proxyRes.destroy()
          req.destroy()
          resolve()
          return
        }

        if (!injectHtml) {
          proxyRes.pipe(res)
          proxyRes.on('error', () => res.destroy())
          req.on('aborted', () => proxyRes.destroy())
          res.on('close', () => proxyRes.destroy())
          proxyRes.on('end', resolve)
          return
        }

        // Buffer the HTML page, inject the compatibility script, then send.
        // If the page is larger than the cap (a mis-detected binary with an
        // html content type), fall back to a transparent stream.
        const chunks = []
        let size = 0
        let overflowing = false
        proxyRes.on('data', (chunk) => {
          if (overflowing) {
            res.write(chunk)
            return
          }
          size += chunk.length
          if (size > HTML_BUFFER_CAP) {
            overflowing = true
            res.write(Buffer.concat(chunks))
            res.write(chunk)
            chunks.length = 0
            return
          }
          chunks.push(chunk)
        })
        proxyRes.on('error', () => res.destroy())
        req.on('aborted', () => proxyRes.destroy())
        res.on('close', () => proxyRes.destroy())
        proxyRes.on('end', () => {
          if (overflowing) {
            res.end()
          } else {
            const html = Buffer.concat(chunks).toString('utf8')
            res.end(injectIntoHtml(html, htmlInjection.script))
          }
          resolve()
        })
      })
      // The timeout guards the request phase only: once the upstream sent
      // response headers, the connection may legitimately stay open (SSE
      // event streams, long polls) without further data for a long time.
      const timeout = setTimeout(() => {
        proxyReq.destroy(new Error('upstream timeout'))
      }, timeoutMs)
      proxyReq.once('response', () => clearTimeout(timeout))
      proxyReq.on('error', (err) => {
        clearTimeout(timeout)
        audit?.warn('proxy-error', { target: targetAuthority, error: err.message })
        if (res.headersSent) {
          res.destroy()
        } else {
          try {
            res.writeHead(502, { 'content-type': 'text/plain; charset=utf-8' })
            res.end('Bad Gateway: upstream unavailable')
          } catch {
            res.destroy()
          }
        }
        resolve()
      })
      req.pipe(proxyReq)
      req.on('error', () => proxyReq.destroy())
    })
  }

  /**
   * Tunnel a WebSocket upgrade. Authentication must already have passed.
   * @param {import('node:http').IncomingMessage} req
   * @param {import('node:net').Socket} socket
   * @param {Buffer} head
   */
  function proxyUpgrade(req, socket, head) {
    const target = net.connect(targetPort, targetHost)
    upgradeSockets.add(target)
    const cleanup = () => {
      upgradeSockets.delete(target)
      socket.destroy()
      target.destroy()
    }
    target.once('error', (err) => {
      audit?.warn('proxy-upgrade-error', { target: targetAuthority, error: err.message })
      cleanup()
    })
    socket.once('error', cleanup)
    socket.once('close', () => {
      upgradeSockets.delete(target)
      target.destroy()
    })
    target.once('close', () => {
      upgradeSockets.delete(target)
      socket.destroy()
    })

    const lines = [
      `${req.method} ${req.url} HTTP/1.1`,
      `Host: ${targetAuthority}`,
      'Connection: Upgrade',
      `Upgrade: ${String(req.headers.upgrade ?? 'websocket')}`,
    ]
    for (const [name, value] of Object.entries(forwardableHeaders(req, cookieName, { originAuthority }))) {
      if (name === 'host' || name === 'connection' || name === 'upgrade') continue
      lines.push(`${name}: ${value}`)
    }
    const requestBytes = Buffer.concat([
      Buffer.from(`${lines.join('\r\n')}\r\n\r\n`, 'latin1'),
      Buffer.isBuffer(head) ? head : Buffer.alloc(0),
    ])

    target.on('connect', () => {
      target.write(requestBytes)
      socket.pipe(target)
      target.pipe(socket)
    })
  }

  return {
    proxyHttp,
    proxyUpgrade,
    /** @returns {number} live upgraded sockets (stats only) */
    upgradedSocketCount() {
      return upgradeSockets.size
    },
    close() {
      for (const socket of upgradeSockets) socket.destroy()
      upgradeSockets.clear()
    },
  }
}
