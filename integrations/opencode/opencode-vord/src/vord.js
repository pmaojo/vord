/**
 * Thin process wrappers around the vord CLI. Every judgement stays in vord;
 * this module only moves bytes in and out.
 * @module opencode-vord/vord
 */

import { spawn } from 'node:child_process'

/**
 * @typedef {object} VordRunOptions
 * @property {string} command - the vord executable.
 * @property {string} cwd - the repository root vord runs in.
 * @property {number} timeoutMs - kill vord after this long.
 * @property {AbortSignal} [signal] - the caller's cancellation.
 * @property {string} [input] - written to vord's stdin.
 */

/**
 * Run vord once and collect its output. Rejects only when vord could not be
 * started or was killed; a non-zero exit is returned for the caller to read,
 * since several vord commands use exit codes as verdicts.
 * @param {string[]} args
 * @param {VordRunOptions} options
 * @returns {Promise<{ code: number, stdout: string, stderr: string }>}
 */
export function runVord(args, { command, cwd, timeoutMs, signal, input }) {
  return new Promise((resolvePromise, reject) => {
    const child = spawn(command, args, {
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
      if (code === null) {
        reject(new Error(`vord ${args.join(' ')} was killed (${killedBy}): ${stderr.trim()}`))
        return
      }
      resolvePromise({ code, stdout, stderr })
    })
    child.stdin.on('error', () => { /* vord may exit before reading; `close` reports it */ })
    child.stdin.end(input ?? '')
  })
}

/**
 * Runs `vord hook claude-code` with one payload on stdin and returns its
 * parsed JSON verdict. vord always exits 0 on this path and prints nothing
 * when it has no objection, so an empty stdout is "silent", not an error.
 * @param {Record<string, unknown>} payload
 * @param {Omit<VordRunOptions, 'input'>} options
 * @returns {Promise<any | undefined>} the verdict object, or `undefined` when vord had nothing to say.
 */
export async function runVordHook(payload, options) {
  const { code, stdout, stderr } = await runVord(['hook', 'claude-code'], { ...options, input: JSON.stringify(payload) })
  if (code !== 0) throw new Error(`vord exited ${code}: ${stderr.trim()}`)
  const text = stdout.trim()
  if (text.length === 0) return undefined
  try {
    return JSON.parse(text)
  } catch (error) {
    throw new Error(`vord printed unparseable output: ${String(error)}`)
  }
}

/**
 * `vord agent baseline`: record what the analyzer sees over `scope` now.
 * @param {{ scope: string, out: string }} target
 * @param {Omit<VordRunOptions, 'input'>} options
 */
export async function recordBaseline({ scope, out }, options) {
  const { code, stderr } = await runVord(['agent', 'baseline', '--scope', scope, '--out', out], options)
  if (code !== 0) throw new Error(`vord agent baseline exited ${code}: ${stderr.trim()}`)
}

/**
 * `vord agent done`: has the task introduced nothing the baseline lacked
 * (and removed `rule`, when one is named)?
 * @param {{ scope: string, baseline: string, rule?: string }} target
 * @param {Omit<VordRunOptions, 'input'>} options
 * @returns {Promise<{ done: boolean, reason: string }>}
 */
export async function analyzerVerdict({ scope, baseline, rule }, options) {
  const args = ['agent', 'done', '--json', '--scope', scope, '--baseline', baseline, ...rule ? ['--rule', rule] : []]
  const { code, stdout, stderr } = await runVord(args, options)
  if (code !== 0 && code !== 3) throw new Error(`vord agent done exited ${code}: ${stderr.trim()}`)
  const verdict = JSON.parse(stdout.trim())
  if (typeof verdict?.done !== 'boolean') throw new Error(`vord agent done printed no verdict: ${stdout.trim()}`)
  return { done: verdict.done, reason: String(verdict.reason ?? '') }
}

/**
 * `vord holes --json`: the holes still waiting for hand-written code.
 * @param {{ scope: string }} target
 * @param {Omit<VordRunOptions, 'input'>} options
 * @returns {Promise<Array<{ kind: string, file: string, name: string, line: number, end_line: number, reason: string, export?: string }>>}
 */
export async function pendingHoles({ scope }, options) {
  const { code, stdout, stderr } = await runVord(['holes', scope, '--json'], options)
  if (code !== 0) throw new Error(`vord holes exited ${code}: ${stderr.trim()}`)
  const holes = JSON.parse(stdout.trim())
  if (!Array.isArray(holes)) throw new Error(`vord holes printed no list: ${stdout.trim()}`)
  return holes
}
