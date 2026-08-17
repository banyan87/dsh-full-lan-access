// compat.js — browser-compatibility shims for the DSH web client.
//
// Two plain-HTTP realities of LAN serving break the DSH client:
//
// 1. `crypto.randomUUID()` exists only in secure contexts (HTTPS or
//    localhost). The DSH client calls it directly for every message and RPC
//    id, so pages served over `http://<lan-ip>:3081` throw
//    "crypto.randomUUID is not a function". The gateway injects a tiny
//    polyfill (backed by `crypto.getRandomValues`, which is available in
//    non-secure contexts) into HTML responses.
//
// 2. DSH's `/api` trust fence compares the Origin header against the Host
//    header it receives. The gateway already rewrites Host to the upstream
//    loopback authority, so the Origin is rewritten to match (see
//    policy.forwardableHeaders) — otherwise every request carrying an
//    Origin (POST/fetch/WebSocket upgrades) is rejected with 403 and
//    privileged RPCs (settings, plugin inventory, model discovery) break.

/** v4 UUID from 16 random bytes (RFC 4122 §4.4). */
export const RANDOM_UUID_POLYFILL = `<script>
(function () {
  'use strict';
  var c = globalThis.crypto;
  if (!c || typeof c.randomUUID === 'function') return;
  try {
    Object.defineProperty(c, 'randomUUID', {
      value: function randomUUID() {
        var b = new Uint8Array(16);
        c.getRandomValues(b);
        b[6] = (b[6] & 0x0f) | 0x40; // version 4
        b[8] = (b[8] & 0x3f) | 0x80; // variant 10
        var h = [];
        for (var i = 0; i < 16; i++) h.push(b[i].toString(16).padStart(2, '0'));
        return h[0] + h[1] + h[2] + h[3] + '-' + h[4] + h[5] + '-' + h[6] + h[7]
          + '-' + h[8] + h[9] + '-' + h[10] + h[11] + h[12] + h[13] + h[14] + h[15];
      },
      configurable: true
    });
  } catch (e) { /* never break the page over a shim */ }
})();
<\/script>`

/**
 * Decide whether a proxied response is injectable HTML: the content type is
 * text/html and the body is identity-encoded (we do not decompress).
 * @param {string | string[] | undefined} contentType
 * @param {string | string[] | undefined} contentEncoding
 * @returns {boolean}
 */
export function isInjectableHtml(contentType, contentEncoding) {
  if (contentEncoding !== undefined) return false
  const type = Array.isArray(contentType) ? contentType[0] : contentType
  return typeof type === 'string' && /^text\/html(?:;|$)/i.test(type.trim())
}

/**
 * Inject a script into an HTML document before `</head>` (falling back to
 * appending at the end when no head close tag exists).
 * @param {string} html
 * @param {string} script
 * @returns {string}
 */
export function injectIntoHtml(html, script) {
  const headEnd = html.indexOf('</head>')
  if (headEnd !== -1) {
    return html.slice(0, headEnd) + script + html.slice(headEnd)
  }
  const bodyEnd = html.indexOf('</body>')
  if (bodyEnd !== -1) {
    return html.slice(0, bodyEnd) + script + html.slice(bodyEnd)
  }
  return html + script
}
