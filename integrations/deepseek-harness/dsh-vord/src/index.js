/**
 * vord's write guardrail as a native DeepSeek Harness plugin.
 *
 * Every `write`, `edit` and `str_replace_editor` call is judged by the same
 * `vord hook claude-code` a Claude Code session uses — same
 * `vord-policy.toml`, protected paths, Gherkin and test evidence, single-use
 * approvals, circuit breaker and `.vord-audit.jsonl` — but on dsh's own
 * extension points rather than through the Claude Code hook bridge:
 *
 * - `tools/pre-execute`: a policy violation denies the call before the bytes
 *   reach disk; the reason names the rule and the line.
 * - `tools/post-execute`: what landed is re-judged from disk; a violation
 *   blocks the result with corrective feedback, an advisory rides along as
 *   context for the next request. A `bash` result feeds vord's test-evidence
 *   ledger.
 * - `agent/created` + `agent/turn-stopping`: the analyzer is the definition
 *   of done. A baseline is recorded when the session starts; a turn cannot
 *   close while the analyzer sees findings the baseline lacked (or a named
 *   target rule still fires), nor while `[[test_required]]` evidence is
 *   pending. The objection steers the agent into another step.
 *
 * Tool names are matched natively, so the bridge's case-sensitive
 * `Edit|Write` vs `edit|write` matcher pitfall does not exist here.
 * @module dsh-vord
 */

import { randomUUID } from 'node:crypto'
import { existsSync } from 'node:fs'
import { hookPayload, sessionCwd, shellResponse, SHELL_TOOL, writeCall } from './payload.js'
import { join } from 'node:path'
import { analyzerVerdict, recordBaseline, runVordHook } from './vord.js'

/** Cordis plugin name used by loader diagnostics. */
export const name = 'vord'

/** The producer source stamped on every message this plugin adds. */
const SOURCE = Object.freeze({ kind: 'vord' })

/**
 * @typedef {object} Config
 * @property {string} [command] - vord executable; default `vord` on PATH.
 * @property {number} [timeoutMs] - per-judgement timeout; default 60000.
 * @property {boolean} [failClosed] - deny a write when vord itself fails; default false (fail open, as vord's own hook does).
 * @property {number} [maxStopContinuations] - consecutive forced continuations before the Stop gate yields; default 3.
 * @property {boolean} [analyzerAsDone] - hold a turn open while the analyzer sees findings the session's baseline lacked; default true.
 * @property {string} [doneScope] - path the baseline is taken over and re-scanned; default `.`.
 * @property {string} [doneRule] - a rule every task in this profile must eliminate from the scope.
 */

/**
 * Where a session's baseline lives: one file per session, so concurrent or
 * resumed sessions in one workspace never compare against each other's.
 * @param {string} cwd
 * @param {string} sessionId
 */
export function baselinePath(cwd, sessionId) {
  return join(cwd, '.vord', 'sessions', `${sessionId.replace(/[^A-Za-z0-9_.-]/g, '_')}.baseline.json`)
}

/**
 * A user-role message in the shape `createUserMessage` from
 * `@deepseek-ai/dsh-llm` produces: fresh id, deep-frozen. Built here rather
 * than imported because a plugin installed into a profile with
 * `dsh plugin add` cannot resolve dsh's own packages at runtime; this keeps
 * dsh-vord free of runtime dependencies.
 * @param {string} text
 */
export function contextMessage(text) {
  const content = Object.freeze([Object.freeze({ type: 'text', text })])
  return Object.freeze({ content, source: SOURCE, role: 'user', id: randomUUID() })
}

/**
 * @param {import('@deepseek-ai/cordis').Context} ctx
 * @param {Config} [config]
 */
export function apply(ctx, config = {}) {
  const command = config.command ?? 'vord'
  const timeoutMs = config.timeoutMs ?? 60_000
  const failClosed = config.failClosed ?? false
  const maxStopContinuations = config.maxStopContinuations ?? 3
  const analyzerAsDone = config.analyzerAsDone ?? true
  const doneScope = config.doneScope ?? '.'
  const doneRule = config.doneRule
  /** @type {WeakMap<object, string>} the baseline each live agent is judged against */
  const baselines = new WeakMap()
  /** @type {WeakMap<object, number>} */
  const stopStreak = new WeakMap()

  /**
   * @param {Record<string, unknown>} payload
   * @param {string} cwd
   * @param {AbortSignal | undefined} signal
   * @returns {Promise<{ ok: true, verdict: any } | { ok: false, error: unknown }>}
   */
  async function judge(payload, cwd, signal) {
    try {
      return { ok: true, verdict: await runVordHook(payload, { command, cwd, timeoutMs, signal }) }
    } catch (error) {
      ctx.logger.warn(`vord: ${payload.hook_event_name} judgement failed: ${String(error)}`)
      return { ok: false, error }
    }
  }

  ctx.on('tools/pre-execute', async (exec, next) => {
    const cwd = sessionCwd(exec)
    const call = writeCall(exec.name, exec.arguments, cwd)
    if (!call) return next()
    const outcome = await judge(hookPayload('PreToolUse', cwd, call.tool_name, call.tool_input), cwd, exec.signal)
    if (!outcome.ok) {
      return failClosed
        ? { kind: 'deny', reason: `vord could not judge this write (${String(outcome.error)}); failClosed is set.` }
        : next()
    }
    const decision = outcome.verdict?.hookSpecificOutput
    if (decision?.permissionDecision === 'deny') {
      return { kind: 'deny', reason: decision.permissionDecisionReason ?? 'denied by vord policy' }
    }
    return next()
  })

  ctx.on('tools/post-execute', async (exec, result, next) => {
    const cwd = sessionCwd(exec)
    let payload
    if (exec.name === SHELL_TOOL) {
      const commandLine = exec.arguments?.command
      if (typeof commandLine !== 'string') return next()
      payload = hookPayload('PostToolUse', cwd, 'Bash', { command: commandLine }, shellResponse(result))
    } else {
      if (result.isError) return next()
      const call = writeCall(exec.name, exec.arguments, cwd)
      if (!call) return next()
      payload = hookPayload('PostToolUse', cwd, call.tool_name, call.tool_input)
    }
    const outcome = await judge(payload, cwd, exec.signal)
    if (!outcome.ok || !outcome.verdict) return next()
    if (outcome.verdict.decision === 'block') {
      return { kind: 'block', feedback: [{ type: 'text', text: outcome.verdict.reason ?? 'blocked by vord policy' }] }
    }
    const advisory = outcome.verdict.hookSpecificOutput?.additionalContext
    const downstream = await next()
    if (typeof advisory !== 'string' || advisory.length === 0) return downstream
    return {
      ...downstream,
      additionalContexts: [contextMessage(advisory), ...downstream.additionalContexts ?? []],
    }
  })

  if (analyzerAsDone) {
    // Record the baseline before the agent's first step: AgentLoop awaits
    // `agent/created` initialisation before it starts queued work. A resumed
    // session keeps the baseline it started with.
    ctx.on('agent/created', async ({ agent, signal }) => {
      const cwd = sessionCwd({ agent })
      const sessionId = agent.session?.header?.id
      if (typeof sessionId !== 'string') return
      const out = baselinePath(cwd, sessionId)
      try {
        if (!existsSync(out)) await recordBaseline({ scope: doneScope, out }, { command, cwd, timeoutMs, signal })
        baselines.set(agent, out)
      } catch (error) {
        // Without a baseline there is nothing to judge against; the Stop
        // gate then falls back to test evidence alone rather than guessing.
        ctx.logger.warn(`vord: could not record the analyzer baseline: ${String(error)}`)
      }
    })
  }

  /**
   * Every objection vord has to this turn closing, as one message, or
   * `undefined` when the turn may close.
   * @param {any} agent
   * @param {AbortSignal | undefined} signal
   */
  async function stopObjections(agent, signal) {
    const cwd = sessionCwd({ agent })
    const options = { command, cwd, timeoutMs, signal }
    const objections = []
    const evidence = await judge({ hook_event_name: 'Stop', cwd }, cwd, signal)
    if (evidence.ok && evidence.verdict?.decision === 'block') {
      objections.push(evidence.verdict.reason ?? 'vord: test evidence is still pending')
    }
    const baseline = baselines.get(agent)
    if (baseline) {
      try {
        const verdict = await analyzerVerdict({ scope: doneScope, baseline, ...doneRule ? { rule: doneRule } : {} }, options)
        if (!verdict.done) objections.push(`vord: ${verdict.reason}`)
      } catch (error) {
        ctx.logger.warn(`vord: analyzer verdict failed: ${String(error)}`)
      }
    }
    return objections.length === 0 ? undefined : objections.join('\n\n')
  }

  ctx.on('agent/turn-stopping', async ({ agent, signal }) => {
    const objection = await stopObjections(agent, signal)
    if (objection === undefined) {
      stopStreak.delete(agent)
      return
    }
    const streak = (stopStreak.get(agent) ?? 0) + 1
    if (streak > maxStopContinuations) {
      // The agent has been sent back this many times in a row without
      // satisfying vord; let the turn close rather than loop forever. The
      // findings and pending evidence remain, and still fail CI's gate.
      ctx.logger.warn(`vord: Stop gate yielded after ${maxStopContinuations} forced continuations`)
      stopStreak.delete(agent)
      return
    }
    stopStreak.set(agent, streak)
    agent.steer(contextMessage(objection))
  })
}
