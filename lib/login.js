// login.js — the gateway's self-contained login page and CSRF handling.
//
// The page is a single HTML string with no external assets, inline styles,
// and a password form. It respects the client's color scheme. CSRF tokens
// are bound to a double-submit cookie plus a hidden form field.

import { randomBytes } from 'node:crypto'

/** Generate a fresh CSRF token (hex, 32 bytes). */
export function newCsrfToken() {
  return randomBytes(32).toString('hex')
}

/**
 * Render the login page.
 * @param {{ csrf: string, error?: string | null, retryAfterSec?: number, branding?: string, passwordConfigured?: boolean }} options
 * @returns {string}
 */
export function renderLoginPage(options) {
  const error = options.error ?? null
  const retryAfterSec = options.retryAfterSec ?? 0
  const branding = options.branding ?? 'DeepSeek Harness — LAN Access'
  const errorHtml = error === null
    ? ''
    : `<div class="error" role="alert">${escapeHtml(error)}</div>`
  const lockoutHtml = retryAfterSec > 0
    ? `<div class="error" role="alert">Too many attempts. Try again in ${Math.ceil(retryAfterSec)} seconds.</div>`
    : ''
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>${escapeHtml(branding)}</title>
<style>
  :root { color-scheme: light dark; }
  * { box-sizing: border-box; }
  body {
    margin: 0; min-height: 100vh; display: flex; align-items: center; justify-content: center;
    font-family: system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
    background: #f5f6f8; color: #1c1e21;
  }
  @media (prefers-color-scheme: dark) {
    body { background: #17181b; color: #e8eaed; }
    .card { background: #232428; border-color: #33363c; }
    input { background: #2c2e33; color: #e8eaed; border-color: #44474e; }
  }
  .card {
    background: #fff; border: 1px solid #e2e4e8; border-radius: 12px;
    padding: 32px; width: min(92vw, 360px); box-shadow: 0 8px 30px rgba(0,0,0,.08);
  }
  h1 { font-size: 17px; margin: 0 0 6px; }
  p.sub { font-size: 13px; color: #6b7280; margin: 0 0 20px; }
  label { display: block; font-size: 13px; margin-bottom: 6px; }
  input[type=password] {
    width: 100%; padding: 10px 12px; font-size: 15px; border-radius: 8px;
    border: 1px solid #d5d8dd; outline: none; margin-bottom: 16px;
  }
  input[type=password]:focus { border-color: #4f7cff; }
  button {
    width: 100%; padding: 10px 12px; font-size: 15px; font-weight: 600; color: #fff;
    background: #2f6fed; border: 0; border-radius: 8px; cursor: pointer;
  }
  button:hover { background: #265fd4; }
  .error {
    background: #fdecec; color: #b3261e; border: 1px solid #f5c6c6; border-radius: 8px;
    padding: 10px 12px; font-size: 13px; margin-bottom: 16px;
  }
  @media (prefers-color-scheme: dark) { .error { background: #3a2222; color: #ff9a94; border-color: #5c3333; } }
  .foot { margin-top: 18px; font-size: 12px; color: #9aa0a8; text-align: center; }
</style>
</head>
<body>
  <form class="card" method="post" action="/__lan_gate/login" autocomplete="off">
    <h1>${escapeHtml(branding)}</h1>
    <p class="sub">Sign in to access this DeepSeek Harness instance from the LAN.</p>
    ${errorHtml}
    ${lockoutHtml}
    <input type="hidden" name="csrf" value="${escapeHtml(options.csrf)}">
    <label for="password">Password</label>
    <input type="password" id="password" name="password" required autofocus autocomplete="current-password">
    <button type="submit">Sign in</button>
    <div class="foot">Requests are rate-limited and audited.</div>
  </form>
</body>
</html>`
}

/** Escape text for safe embedding in HTML. */
export function escapeHtml(text) {
  return String(text)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;')
}
