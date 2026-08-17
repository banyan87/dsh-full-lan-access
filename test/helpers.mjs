// helpers.mjs — shared test utilities.
//
// ensureSelfLink() makes the project's own package resolvable from its
// node_modules (Node self-reference does not work through the Cordis
// Loader's baseUrl-based resolver), mirroring how `dsh plugin add` installs
// a plugin into a profile.

import { existsSync, mkdirSync, symlinkSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'

const TEST_DIR = dirname(fileURLToPath(import.meta.url))

/** The project root (the dsh-full-lan-access package directory). */
export const PROJECT_ROOT = dirname(TEST_DIR)

export function ensureSelfLink() {
  const link = join(PROJECT_ROOT, 'node_modules', 'dsh-full-lan-access')
  if (existsSync(link)) return link
  mkdirSync(dirname(link), { recursive: true })
  try {
    symlinkSync(PROJECT_ROOT, link, process.platform === 'win32' ? 'junction' : 'dir')
  } catch {
    // Best effort — if linking fails the loader test skips itself.
  }
  return link
}
