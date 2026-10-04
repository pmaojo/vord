/**
 * Runs `vord hook claude-code` with one payload on stdin and returns its
 * parsed JSON verdict. vord always exits 0 on this path and prints nothing
 * when it has no objection, so an empty stdout is "silent", not an error.
 * @module dsh-vord/vord
 */

import { spawn } from 'node:child_process'

/**
 * @typedef {object} VordRunOptions
 * @property {string} command - the vord executable.
 * @property {string} cwd - the repository root the payload is judged against.
 * @property {number} timeoutMs - kill vord after this long.
 * @property {AbortSignal} [signal] - the tool call's cancellation.
 */

/**
 * @param {Record<string, unknown>} payload
 * @param {VordRunOptions} options
 * @returns {Promise<any | undefined>} the verdict object, or `undefined` when vord had nothing to say.
 */
export function runVordHook(payload, { command, cwd, timeoutMs, signal }) {
  return new Promise((resolvePromise, reject) => {
    const child = spawn(command, ['hook', 'claude-code'], {
      cwd,
      stdio: ['pipe', 'pipe', 'pipe'],
      timeout: timeoutMs,
      ...signal ? { signal } : {},
    })
    let stdout = ''
    let stderr = ''
    child.stdout.setEncoding('utf8').on('data', (chunk) => { stdout += chunk })
    child.stderr.setEncoding('utf8').on('data', (chunk) => { stderr += chunk })
    child.on('error', reject)
    child.on('close', (code, killedBy) => {
      if (code !== 0) {
        reject(new Error(`vord exited ${code ?? killedBy}: ${stderr.trim()}`))
        return
      }
      const text = stdout.trim()
      if (text.length === 0) {
        resolvePromise(undefined)
        return
      }
      try {
        resolvePromise(JSON.parse(text))
      } catch (error) {
        reject(new Error(`vord printed unparseable output: ${String(error)}`))
      }
    })
    child.stdin.on('error', () => { /* vord may exit before reading; `close` reports it */ })
    child.stdin.end(JSON.stringify(payload))
  })
}
