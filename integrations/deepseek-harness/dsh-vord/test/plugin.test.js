import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, readFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { apply } from '../src/index.js'
import { accept, allow, execution, fakeAgent, fakeContext } from './helpers.js'

const FAKE_VORD = fileURLToPath(new URL('./fixtures/fake-vord.mjs', import.meta.url))

/** Mount the plugin against the fake vord, which prints `output`. */
function mount(output, extra = {}) {
  const dir = mkdtempSync(join(tmpdir(), 'dsh-vord-plugin-'))
  const log = join(dir, 'payloads.jsonl')
  process.env.FAKE_VORD_LOG = log
  process.env.FAKE_VORD_OUTPUT = output === undefined ? '' : JSON.stringify(output)
  delete process.env.FAKE_VORD_EXIT
  delete process.env.FAKE_VORD_DONE
  delete process.env.FAKE_VORD_HOLES
  const ctx = fakeContext()
  apply(ctx, { command: FAKE_VORD, ...extra })
  const payloads = () => {
    try {
      return readFileSync(log, 'utf8').trim().split('\n').filter(Boolean).map(line => JSON.parse(line)).filter(entry => !entry.argv)
    } catch {
      return []
    }
  }
  const calls = () => {
    try {
      return readFileSync(log, 'utf8').trim().split('\n').filter(Boolean).map(line => JSON.parse(line)).filter(entry => entry.argv).map(entry => entry.argv)
    } catch {
      return []
    }
  }
  return { ctx, dir, payloads, calls, agent: fakeAgent(dir) }
}

test('a denied write never reaches the tool', async () => {
  const { ctx, agent, payloads } = mount({
    hookSpecificOutput: { hookEventName: 'PreToolUse', permissionDecision: 'deny', permissionDecisionReason: 'python:subprocess-shell-true at line 3' },
  })
  const decision = await ctx.fire('tools/pre-execute', execution('write', { file_path: 'a.py', content: 'x' }, agent), allow)
  assert.deepEqual(decision, { kind: 'deny', reason: 'python:subprocess-shell-true at line 3' })
  const [payload] = payloads()
  assert.equal(payload.hook_event_name, 'PreToolUse')
  assert.equal(payload.tool_name, 'Write')
  assert.equal(payload.cwd, agent.session.header.cwd)
})

test('a silent verdict delegates to the next listener', async () => {
  const { ctx, agent } = mount(undefined)
  const decision = await ctx.fire('tools/pre-execute', execution('edit', { file_path: 'a.py', old_string: 'a', new_string: 'b' }, agent), allow)
  assert.deepEqual(decision, { kind: 'allow' })
})

test('non-write tools are never sent to vord', async () => {
  const { ctx, agent, payloads } = mount(undefined)
  await ctx.fire('tools/pre-execute', execution('read', { file_path: 'a.py' }, agent), allow)
  assert.equal(payloads().length, 0)
})

test('vord failing fails open by default and closed when asked', async () => {
  const open = mount(undefined)
  process.env.FAKE_VORD_EXIT = '1'
  assert.deepEqual(await open.ctx.fire('tools/pre-execute', execution('write', { file_path: 'a', content: 'x' }, open.agent), allow), { kind: 'allow' })
  assert.equal(open.ctx.warnings.length, 1)

  const closed = mount(undefined, { failClosed: true })
  process.env.FAKE_VORD_EXIT = '1'
  const decision = await closed.ctx.fire('tools/pre-execute', execution('write', { file_path: 'a', content: 'x' }, closed.agent), allow)
  assert.equal(decision.kind, 'deny')
  delete process.env.FAKE_VORD_EXIT
})

test('a post-write violation blocks the result with feedback', async () => {
  const { ctx, agent } = mount({ decision: 'block', reason: 'already written: fix it' })
  const decision = await ctx.fire('tools/post-execute', execution('write', { file_path: 'a', content: 'x' }, agent), { isError: false, value: {}, content: [] }, accept)
  assert.deepEqual(decision, { kind: 'block', feedback: [{ type: 'text', text: 'already written: fix it' }] })
})

test('a post-write advisory rides along as context', async () => {
  const { ctx, agent } = mount({ hookSpecificOutput: { hookEventName: 'PostToolUse', additionalContext: 'consider extracting' } })
  const decision = await ctx.fire('tools/post-execute', execution('write', { file_path: 'a', content: 'x' }, agent), { isError: false, value: {}, content: [] }, accept)
  assert.equal(decision.kind, 'accept')
  assert.equal(decision.additionalContexts.length, 1)
  assert.equal(decision.additionalContexts[0].content[0].text, 'consider extracting')
  assert.deepEqual(decision.additionalContexts[0].source, { kind: 'vord' })
})

test('a bash run is reported as Bash with its exit code', async () => {
  const { ctx, agent, payloads } = mount(undefined)
  await ctx.fire('tools/post-execute', execution('bash', { command: 'cargo test' }, agent), { isError: false, value: { exitCode: 0 }, content: [] }, accept)
  const [payload] = payloads()
  assert.equal(payload.tool_name, 'Bash')
  assert.deepEqual(payload.tool_input, { command: 'cargo test' })
  assert.deepEqual(payload.tool_response, { exit_code: 0 })
})

test('pending test evidence steers the agent, then yields after the cap', async () => {
  const { ctx, agent, payloads } = mount({ decision: 'block', reason: 'run the tests' }, { maxStopContinuations: 2 })
  const stopping = { agent, turn: 1, signal: new AbortController().signal }
  await ctx.fire('agent/turn-stopping', stopping)
  await ctx.fire('agent/turn-stopping', stopping)
  await ctx.fire('agent/turn-stopping', stopping)
  assert.equal(agent.steered.length, 2, 'third stop yields instead of looping')
  assert.equal(agent.steered[0].content[0].text, 'run the tests')
  assert.equal(payloads()[0].hook_event_name, 'Stop')
})

test('the analyzer is the definition of done: new findings hold the turn open', async () => {
  const { ctx, agent, calls, dir } = mount(undefined)
  await ctx.fire('agent/created', { agent, source: 'new', signal: new AbortController().signal })
  const [baseline] = calls()
  assert.deepEqual(baseline.slice(0, 4), ['agent', 'baseline', '--scope', '.'])
  assert.ok(baseline.at(-1).startsWith(join(dir, '.vord', 'sessions')), 'baseline is per session, in the workspace')

  const stopping = { agent, turn: 1, signal: new AbortController().signal }
  await ctx.fire('agent/turn-stopping', stopping)
  assert.equal(agent.steered.length, 0, 'the analyzer agrees, so the turn closes')

  process.env.FAKE_VORD_DONE = JSON.stringify({ done: false, reason: 'your changes introduced 1 finding(s)' })
  await ctx.fire('agent/turn-stopping', stopping)
  assert.equal(agent.steered.length, 1)
  assert.match(agent.steered[0].content[0].text, /introduced 1 finding/)
  const done = calls().at(-1)
  assert.deepEqual(done.slice(0, 3), ['agent', 'done', '--json'])
  assert.equal(done[done.indexOf('--baseline') + 1], baseline.at(-1), 'judged against the recorded baseline')
})

test('a resumed session keeps the baseline it started with', async () => {
  const { ctx, agent, calls } = mount(undefined)
  const created = { agent, source: 'new', signal: new AbortController().signal }
  await ctx.fire('agent/created', created)
  await ctx.fire('agent/created', { ...created, source: 'resume' })
  assert.equal(calls().filter(argv => argv[1] === 'baseline').length, 1)
})

test('test evidence and analyzer objections are combined into one steer', async () => {
  const { ctx, agent } = mount({ decision: 'block', reason: 'run the tests' })
  await ctx.fire('agent/created', { agent, source: 'new', signal: new AbortController().signal })
  process.env.FAKE_VORD_DONE = JSON.stringify({ done: false, reason: 'target remains' })
  await ctx.fire('agent/turn-stopping', { agent, turn: 1, signal: new AbortController().signal })
  assert.equal(agent.steered.length, 1)
  assert.match(agent.steered[0].content[0].text, /run the tests[\s\S]*target remains/)
})

const HOLES = JSON.stringify([
  { kind: 'marker', file: 'internal/order/service.go', name: 'order-create', line: 5, end_line: 7, reason: 'empty or placeholder' },
  { kind: 'marker', file: 'internal/user/service.go', name: 'user-create', line: 5, end_line: 7, reason: 'empty or placeholder' },
])

test('a hole the session wrote to but left pending holds the turn open', async () => {
  const { ctx, agent, dir, calls } = mount(undefined)
  process.env.FAKE_VORD_HOLES = HOLES
  const stopping = { agent, turn: 1, signal: new AbortController().signal }
  await ctx.fire('agent/turn-stopping', stopping)
  assert.equal(agent.steered.length, 0, 'holes the session never touched are not its task')
  assert.ok(!calls().some(argv => argv[0] === 'holes'), 'nothing written, nothing to ask vord')

  await ctx.fire('tools/post-execute', execution('write', { file_path: join(dir, 'internal/order/service.go'), content: 'x' }, agent), { isError: false, value: {}, content: [] }, accept)
  await ctx.fire('agent/turn-stopping', stopping)
  assert.equal(agent.steered.length, 1)
  const text = agent.steered[0].content[0].text
  assert.match(text, /1 hole\(s\) still pending/)
  assert.match(text, /internal\/order\/service\.go:5 `order-create`/)
  assert.doesNotMatch(text, /user-create/)
})

test('holesAsDone all holds the turn while any hole in scope is pending, false never does', async () => {
  const all = mount(undefined, { holesAsDone: 'all' })
  process.env.FAKE_VORD_HOLES = HOLES
  await all.ctx.fire('agent/turn-stopping', { agent: all.agent, turn: 1, signal: new AbortController().signal })
  assert.match(all.agent.steered[0].content[0].text, /2 hole\(s\) still pending/)

  const off = mount(undefined, { holesAsDone: false })
  process.env.FAKE_VORD_HOLES = HOLES
  await off.ctx.fire('tools/post-execute', execution('write', { file_path: join(off.dir, 'internal/order/service.go'), content: 'x' }, off.agent), { isError: false, value: {}, content: [] }, accept)
  await off.ctx.fire('agent/turn-stopping', { agent: off.agent, turn: 1, signal: new AbortController().signal })
  assert.equal(off.agent.steered.length, 0)
})
