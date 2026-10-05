/**
 * vord's write guardrail as a native opencode plugin.
 *
 * Every `write`, `edit` and `apply_patch` call is judged by the same
 * `vord hook claude-code` a Claude Code session uses — same
 * `vord-policy.toml`, protected paths, Gherkin and test evidence, single-use
 * approvals, circuit breaker and `.vord-audit.jsonl` — on opencode's own
 * plugin hooks:
 *
 * - `tool.execute.before`: a policy violation throws, so the call fails
 *   before the bytes reach disk and the model reads the rule and the line.
 *   A recursive `rm` (or an `apply_patch` delete) of generated code is
 *   refused the same way.
 * - `tool.execute.after`: what landed is re-judged from disk; a violation
 *   replaces the tool output with corrective feedback, an advisory is
 *   appended to it. A `bash` result feeds vord's test-evidence ledger.
 * - `chat.message`: the analyzer's baseline is recorded before a session's
 *   first request, once, under `.vord/sessions/`.
 * - `session.idle`: opencode has no hook that can veto a turn closing, so the
 *   definition of done is enforced by sending vord's objection (new findings,
 *   pending test evidence, pending holes) back into the session as the next
 *   user message, up to `maxStopContinuations` times in a row.
 * - `experimental.chat.system.transform`: the standing guidance (scaffold with
 *   vord, engine per language, never delete generated output).
 * - `config`: mounts `vord mcp` as the `vord` MCP server unless the
 *   project already configures one.
 * @module opencode-vord
 */

import { existsSync } from 'node:fs'
import { relative } from 'node:path'
import { baselinePath, defaultGuidance, deletesGenerated, deletesGeneratedProject } from './guard.js'
import { deletedFiles, hookPayload, landedWrite, shellResponse, SHELL_TOOL, writeCalls, writtenFiles } from './payload.js'
import { analyzerVerdict, pendingHoles, recordBaseline, runVordHook } from './vord.js'

/**
 * @typedef {object} Options
 * @property {string} [command] - vord executable; default `vord` on PATH.
 * @property {number} [timeoutMs] - per-judgement timeout; default 60000.
 * @property {boolean} [failClosed] - refuse a write when vord itself fails; default false (fail open, as vord's own hook does).
 * @property {number} [maxStopContinuations] - consecutive forced continuations before the done gate yields; default 3.
 * @property {boolean} [analyzerAsDone] - send the session back while the analyzer sees findings its baseline lacked; default true.
 * @property {string} [doneScope] - path the baseline is taken over and re-scanned; default `.`.
 * @property {string} [doneRule] - a rule every task must eliminate from the scope.
 * @property {'touched' | 'all' | false} [holesAsDone] - send the session back while holes stay pending: in files it wrote (`touched`, default), anywhere in `doneScope` (`all`), or never (`false`).
 * @property {boolean | string} [guidance] - standing guidance in the system prompt: `true` (default) the built-in text, a string replaces it, `false` none.
 * @property {boolean | string} [mcp] - mount `vord mcp`: `true` (default) as server `vord`, a string names the server, `false` does not mount it.
 */

const SERVICE = 'vord'

/**
 * @param {import('@opencode-ai/plugin').PluginInput} input
 * @param {Options} [options]
 * @returns {Promise<import('@opencode-ai/plugin').Hooks>}
 */
export async function VordPlugin({ client, directory }, options = {}) {
  const command = options.command ?? 'vord'
  const timeoutMs = options.timeoutMs ?? 60_000
  const failClosed = options.failClosed ?? false
  const maxStopContinuations = options.maxStopContinuations ?? 3
  const analyzerAsDone = options.analyzerAsDone ?? true
  const doneScope = options.doneScope ?? '.'
  const doneRule = options.doneRule
  const holesAsDone = options.holesAsDone ?? 'touched'
  const mcpServer = options.mcp === undefined || options.mcp === true
    ? 'vord'
    : typeof options.mcp === 'string' && options.mcp.trim() !== '' ? options.mcp : undefined
  const tool = (name) => `${(mcpServer ?? 'vord').replace(/[^a-zA-Z0-9_-]/g, '_')}_${name}`
  const guidance = options.guidance === undefined || options.guidance === true
    ? defaultGuidance(tool)
    : typeof options.guidance === 'string' && options.guidance.trim() !== '' ? options.guidance : undefined
  const cwd = directory
  const run = { command, cwd, timeoutMs }

  /** @type {Map<string, string>} child session -> parent session */
  const parents = new Map()
  /** @type {Map<string, string>} the baseline each root session is judged against */
  const baselines = new Map()
  /** @type {Map<string, Set<string>>} workspace-relative files each root session wrote */
  const touched = new Map()
  /** @type {Map<string, number>} consecutive forced continuations per session */
  const stopStreak = new Map()
  /** @type {Set<string>} sessions whose next user message is vord's own objection */
  const steering = new Set()
  /** @type {Set<string>} sessions whose done gate is running */
  const judging = new Set()

  /** @param {string} message */
  function warn(message) {
    client?.app?.log?.({ body: { service: SERVICE, level: 'warn', message } })?.catch?.(() => {})
  }

  /** @param {string} sessionID */
  function rootOf(sessionID) {
    let id = sessionID
    for (let parent = parents.get(id); parent; parent = parents.get(id)) id = parent
    return id
  }

  /**
   * @param {Record<string, unknown>} payload
   * @returns {Promise<{ ok: true, verdict: any } | { ok: false, error: unknown }>}
   */
  async function judge(payload) {
    try {
      return { ok: true, verdict: await runVordHook(payload, run) }
    } catch (error) {
      warn(`${payload.hook_event_name} judgement failed: ${String(error)}`)
      return { ok: false, error }
    }
  }

  /** @param {string} sessionID */
  async function ensureBaseline(sessionID) {
    if (!analyzerAsDone || parents.has(sessionID) || baselines.has(sessionID)) return
    const out = baselinePath(cwd, sessionID)
    try {
      if (!existsSync(out)) await recordBaseline({ scope: doneScope, out }, run)
      baselines.set(sessionID, out)
    } catch (error) {
      // Without a baseline there is nothing to judge against; the done gate
      // then falls back to test evidence and holes rather than guessing.
      warn(`could not record the analyzer baseline: ${String(error)}`)
    }
  }

  /**
   * Every objection vord has to this session stopping, as one message, or
   * `undefined` when it may stop.
   * @param {string} sessionID
   */
  async function stopObjections(sessionID) {
    const objections = []
    const evidence = await judge({ hook_event_name: 'Stop', cwd })
    if (evidence.ok && evidence.verdict?.decision === 'block') {
      objections.push(evidence.verdict.reason ?? 'vord: test evidence is still pending')
    }
    const baseline = baselines.get(sessionID)
    if (baseline) {
      try {
        const verdict = await analyzerVerdict({ scope: doneScope, baseline, ...doneRule ? { rule: doneRule } : {} }, run)
        if (!verdict.done) objections.push(`vord: ${verdict.reason}`)
      } catch (error) {
        warn(`analyzer verdict failed: ${String(error)}`)
      }
    }
    const holes = await holeObjection(sessionID)
    if (holes) objections.push(holes)
    return objections.length === 0 ? undefined : objections.join('\n\n')
  }

  /** @param {string} sessionID */
  async function holeObjection(sessionID) {
    if (!holesAsDone) return undefined
    const files = touched.get(sessionID)
    if (holesAsDone === 'touched' && !files?.size) return undefined
    let holes
    try {
      holes = await pendingHoles({ scope: doneScope }, run)
    } catch (error) {
      warn(`could not list holes: ${String(error)}`)
      return undefined
    }
    const open = holesAsDone === 'all' ? holes : holes.filter((hole) => files.has(hole.file))
    if (open.length === 0) return undefined
    const lines = open.map((hole) => `- ${hole.file}:${hole.line} \`${hole.name || '(unnamed)'}\` (${hole.reason})`)
    return `vord: ${open.length} hole(s) still pending — write the hand-written code inside each one, replacing the placeholder:\n${lines.join('\n')}`
  }

  /** @param {string} sessionID */
  async function onIdle(sessionID) {
    if (parents.has(sessionID) || judging.has(sessionID)) return
    if (!baselines.has(sessionID) && !touched.has(sessionID)) return
    judging.add(sessionID)
    try {
      const objection = await stopObjections(sessionID)
      if (objection === undefined) {
        stopStreak.delete(sessionID)
        return
      }
      const streak = (stopStreak.get(sessionID) ?? 0) + 1
      if (streak > maxStopContinuations) {
        // Sent back this many times in a row without satisfying vord; let the
        // session rest rather than loop forever. The findings and pending
        // evidence remain, and still fail CI's gate.
        warn(`done gate yielded after ${maxStopContinuations} forced continuations`)
        stopStreak.delete(sessionID)
        return
      }
      stopStreak.set(sessionID, streak)
      steering.add(sessionID)
      await client.session.promptAsync({
        path: { id: sessionID },
        body: { parts: [{ type: 'text', text: objection }] },
      })
    } catch (error) {
      steering.delete(sessionID)
      warn(`could not send the done objection: ${String(error)}`)
    } finally {
      judging.delete(sessionID)
    }
  }

  return {
    config: async (config) => {
      if (!mcpServer || config.mcp?.[mcpServer]) return
      config.mcp = { ...config.mcp, [mcpServer]: { type: 'local', command: [command, 'mcp'], enabled: true } }
    },

    event: async ({ event }) => {
      if (event.type === 'session.created') {
        const info = event.properties?.info
        if (info?.parentID) parents.set(info.id, info.parentID)
      } else if (event.type === 'session.idle') {
        await onIdle(event.properties.sessionID)
      } else if (event.type === 'session.deleted') {
        const id = event.properties?.info?.id
        for (const map of [parents, baselines, touched, stopStreak]) map.delete(id)
      }
    },

    'chat.message': async ({ sessionID }) => {
      // A message vord sent keeps the streak; anyone else's resets it.
      if (steering.has(sessionID)) steering.delete(sessionID)
      else stopStreak.delete(sessionID)
      await ensureBaseline(sessionID)
    },

    'experimental.chat.system.transform': async (_input, output) => {
      if (guidance !== undefined) output.system.push(guidance)
    },

    'tool.execute.before': async ({ tool: name }, output) => {
      const args = output.args
      if (name === SHELL_TOOL) {
        const reason = deletesGeneratedProject(args?.command, cwd)
        if (reason) throw new Error(reason)
        return
      }
      for (const file of deletedFiles(name, args, cwd)) {
        const reason = deletesGenerated(file, relative(cwd, file))
        if (reason) throw new Error(reason)
      }
      for (const call of writeCalls(name, args, cwd)) {
        const outcome = await judge(hookPayload('PreToolUse', cwd, call.tool_name, call.tool_input))
        if (!outcome.ok) {
          if (failClosed) throw new Error(`vord could not judge this write (${String(outcome.error)}); failClosed is set.`)
          continue
        }
        const decision = outcome.verdict?.hookSpecificOutput
        if (decision?.permissionDecision === 'deny') {
          throw new Error(decision.permissionDecisionReason ?? 'denied by vord policy')
        }
      }
    },

    'tool.execute.after': async ({ tool: name, sessionID, args }, output) => {
      /** @type {Array<Record<string, unknown>>} */
      let payloads
      if (name === SHELL_TOOL) {
        if (typeof args?.command !== 'string') return
        payloads = [hookPayload('PostToolUse', cwd, 'Bash', { command: args.command }, shellResponse(output))]
      } else {
        const files = writtenFiles(name, args, cwd)
        if (files.length === 0) return
        const root = rootOf(sessionID)
        const set = touched.get(root) ?? new Set()
        for (const file of files) set.add(relative(cwd, file).split('\\').join('/'))
        touched.set(root, set)
        payloads = name === 'apply_patch'
          ? files.map(landedWrite).filter(Boolean).map((call) => hookPayload('PostToolUse', cwd, call.tool_name, call.tool_input))
          : writeCalls(name, args, cwd).map((call) => hookPayload('PostToolUse', cwd, call.tool_name, call.tool_input))
      }
      const blocks = []
      const advisories = []
      for (const payload of payloads) {
        const outcome = await judge(payload)
        if (!outcome.ok || !outcome.verdict) continue
        if (outcome.verdict.decision === 'block') {
          blocks.push(outcome.verdict.reason ?? 'blocked by vord policy')
          continue
        }
        const advisory = outcome.verdict.hookSpecificOutput?.additionalContext
        if (typeof advisory === 'string' && advisory.length > 0) advisories.push(advisory)
      }
      if (blocks.length > 0) {
        output.output = blocks.join('\n\n')
        return
      }
      if (advisories.length > 0) output.output = [output.output, ...advisories].filter(Boolean).join('\n\n')
    },
  }
}

export default { id: 'vord', server: VordPlugin }
