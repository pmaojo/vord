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
 * - `agent/turn-stopping`: a turn cannot close while `[[test_required]]`
 *   evidence is still pending; the objection steers the agent into another
 *   step.
 *
 * Tool names are matched natively, so the bridge's case-sensitive
 * `Edit|Write` vs `edit|write` matcher pitfall does not exist here.
 * @module dsh-vord
 */

import { createUserMessage } from '@deepseek-ai/dsh-llm'
import { hookPayload, sessionCwd, shellResponse, SHELL_TOOL, writeCall } from './payload.js'
import { runVordHook } from './vord.js'

/** Cordis plugin name used by loader diagnostics. */
export const name = 'vord'

/** The producer source stamped on every message this plugin adds. */
const SOURCE = { kind: 'vord' }

/**
 * @typedef {object} Config
 * @property {string} [command] - vord executable; default `vord` on PATH.
 * @property {number} [timeoutMs] - per-judgement timeout; default 60000.
 * @property {boolean} [failClosed] - deny a write when vord itself fails; default false (fail open, as vord's own hook does).
 * @property {number} [maxStopContinuations] - consecutive forced continuations before the Stop gate yields; default 3.
 */

/**
 * @param {string} text
 */
function contextMessage(text) {
  return createUserMessage({ content: [{ type: 'text', text }], source: SOURCE })
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

  ctx.on('agent/turn-stopping', async ({ agent, signal }) => {
    const cwd = sessionCwd({ agent })
    const outcome = await judge({ hook_event_name: 'Stop', cwd }, cwd, signal)
    const blocked = outcome.ok && outcome.verdict?.decision === 'block'
    if (!blocked) {
      stopStreak.delete(agent)
      return
    }
    const streak = (stopStreak.get(agent) ?? 0) + 1
    if (streak > maxStopContinuations) {
      // The agent has been sent back this many times in a row without
      // clearing the ledger; let the turn close rather than loop forever. The
      // pending evidence is still in the ledger and still blocks CI's gate.
      ctx.logger.warn(`vord: Stop gate yielded after ${maxStopContinuations} forced continuations`)
      stopStreak.delete(agent)
      return
    }
    stopStreak.set(agent, streak)
    agent.steer(contextMessage(outcome.verdict.reason ?? 'vord: test evidence is still pending'))
  })
}
