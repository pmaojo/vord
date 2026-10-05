import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import plugin, { VordPlugin } from '../src/index.js'

const FAKE_VORD = fileURLToPath(new URL('./fixtures/fake-vord.mjs', import.meta.url))

/** A stand-in for the opencode SDK client: records prompts and logs. */
function fakeClient() {
  const prompts = []
  const logs = []
  return {
    prompts,
    logs,
    app: { log: async (req) => { logs.push(req.body) } },
    session: { promptAsync: async (req) => { prompts.push(req) } },
  }
}

/** Mount the plugin against the fake vord, which prints `output`. */
async function mount(output, extra = {}) {
  const dir = mkdtempSync(join(tmpdir(), 'opencode-vord-plugin-'))
  const log = join(dir, 'payloads.jsonl')
  process.env.FAKE_VORD_LOG = log
  process.env.FAKE_VORD_OUTPUT = output === undefined ? '' : JSON.stringify(output)
  delete process.env.FAKE_VORD_EXIT
  delete process.env.FAKE_VORD_DONE
  delete process.env.FAKE_VORD_HOLES
  const client = fakeClient()
  const hooks = await VordPlugin({ client, directory: dir }, { command: FAKE_VORD, guidance: false, ...extra })
  const entries = () => {
    try {
      return readFileSync(log, 'utf8').trim().split('\n').filter(Boolean).map(line => JSON.parse(line))
    } catch {
      return []
    }
  }
  return {
    hooks,
    client,
    dir,
    payloads: () => entries().filter(entry => !entry.argv),
    calls: () => entries().filter(entry => entry.argv).map(entry => entry.argv),
  }
}

const before = (hooks, tool, args) => hooks['tool.execute.before']({ tool, sessionID: 's1', callID: 'c1' }, { args })
const after = (hooks, tool, args, output = { title: '', output: 'ok', metadata: {} }, sessionID = 's1') =>
  hooks['tool.execute.after']({ tool, sessionID, callID: 'c1', args }, output).then(() => output)

test('the default export is an opencode v1 server plugin', () => {
  assert.equal(plugin.id, 'vord')
  assert.equal(plugin.server, VordPlugin)
})

test('a denied write throws before the tool runs', async () => {
  const { hooks, dir, payloads } = await mount({
    hookSpecificOutput: { hookEventName: 'PreToolUse', permissionDecision: 'deny', permissionDecisionReason: 'python:subprocess-shell-true at line 3' },
  })
  await assert.rejects(before(hooks, 'write', { filePath: 'a.py', content: 'x' }), /python:subprocess-shell-true at line 3/)
  const [payload] = payloads()
  assert.equal(payload.hook_event_name, 'PreToolUse')
  assert.equal(payload.tool_name, 'Write')
  assert.equal(payload.tool_input.file_path, join(dir, 'a.py'))
  assert.equal(payload.cwd, dir)
})

test('an edit is translated to Claude Code argument names', async () => {
  const { hooks, payloads } = await mount(undefined)
  await before(hooks, 'edit', { filePath: '/x/a.py', oldString: 'a', newString: 'b', replaceAll: true })
  assert.deepEqual(payloads()[0].tool_input, { file_path: '/x/a.py', old_string: 'a', new_string: 'b', replace_all: true })
  assert.equal(payloads()[0].tool_name, 'Edit')
})

test('an apply_patch is judged per added file and per hunk', async () => {
  const { hooks, dir, payloads } = await mount(undefined)
  const patchText = [
    '*** Begin Patch',
    '*** Add File: new.py',
    '+import os',
    '+print(1)',
    '*** Update File: old.py',
    '@@ def f():',
    ' a = 1',
    '-b = 2',
    '+b = 3',
    '*** End Patch',
  ].join('\n')
  await before(hooks, 'apply_patch', { patchText })
  const [add, edit] = payloads()
  assert.deepEqual(add.tool_input, { file_path: join(dir, 'new.py'), content: 'import os\nprint(1)\n' })
  assert.deepEqual(edit.tool_input, { file_path: join(dir, 'old.py'), old_string: 'a = 1\nb = 2', new_string: 'a = 1\nb = 3', replace_all: false })
})

test('non-write tools are never sent to vord', async () => {
  const { hooks, payloads } = await mount(undefined)
  await before(hooks, 'read', { filePath: 'a.py' })
  await before(hooks, 'vord_vord_scan', { path: '.' })
  assert.equal(payloads().length, 0)
})

test('vord failing fails open by default and closed when asked', async () => {
  const open = await mount(undefined)
  process.env.FAKE_VORD_EXIT = '1'
  await before(open.hooks, 'write', { filePath: 'a', content: 'x' })
  assert.equal(open.client.logs.length, 1)

  const closed = await mount(undefined, { failClosed: true })
  process.env.FAKE_VORD_EXIT = '1'
  await assert.rejects(before(closed.hooks, 'write', { filePath: 'a', content: 'x' }), /failClosed/)
  delete process.env.FAKE_VORD_EXIT
})

test('a post-write violation replaces the output with feedback', async () => {
  const { hooks } = await mount({ decision: 'block', reason: 'already written: fix it' })
  const output = await after(hooks, 'write', { filePath: 'a', content: 'x' })
  assert.equal(output.output, 'already written: fix it')
})

test('a post-write advisory is appended to the output', async () => {
  const { hooks } = await mount({ hookSpecificOutput: { hookEventName: 'PostToolUse', additionalContext: 'consider extracting' } })
  const output = await after(hooks, 'write', { filePath: 'a', content: 'x' })
  assert.equal(output.output, 'ok\n\nconsider extracting')
})

test('an apply_patch is re-judged from disk', async () => {
  const { hooks, dir, payloads } = await mount(undefined)
  writeFileSync(join(dir, 'new.py'), 'on disk\n')
  await after(hooks, 'apply_patch', { patchText: '*** Begin Patch\n*** Add File: new.py\n+x\n*** End Patch' })
  assert.deepEqual(payloads()[0].tool_input, { file_path: join(dir, 'new.py'), content: 'on disk\n' })
  assert.equal(payloads()[0].hook_event_name, 'PostToolUse')
})

test('a bash result feeds the evidence ledger with its exit code', async () => {
  const { hooks, payloads } = await mount(undefined)
  await after(hooks, 'bash', { command: 'cargo test' }, { title: '', output: '', metadata: { exit: 0 } })
  await after(hooks, 'bash', { command: 'cargo test' }, { title: '', output: '', metadata: { exit: null } })
  const [ok, aborted] = payloads()
  assert.equal(ok.tool_name, 'Bash')
  assert.deepEqual(ok.tool_response, { exit_code: 0 })
  assert.deepEqual(aborted.tool_response, { exit_code: 1 })
})

test('rm -rf of a generated project is refused, other deletions pass', async () => {
  const { hooks, dir } = await mount(undefined)
  mkdirSync(join(dir, 'app', '.vord'), { recursive: true })
  writeFileSync(join(dir, 'app', '.vord', 'generated.json'), JSON.stringify({ files: { 'src/main.rs': { kind: 'regenerable' }, 'README.md': { kind: 'seed' } } }))
  await assert.rejects(before(hooks, 'bash', { command: 'rm -rf app' }), /generated code/)
  await assert.rejects(before(hooks, 'bash', { command: 'cd x && rm -r app/src' }), /generated code/)
  await before(hooks, 'bash', { command: 'rm -rf app/node_modules' })
  await before(hooks, 'bash', { command: 'rm -rf app/README.md' })
  await before(hooks, 'bash', { command: 'rm app/src/main.rs' })
})

test('an apply_patch that deletes generated code is refused', async () => {
  const { hooks, dir } = await mount(undefined)
  mkdirSync(join(dir, '.vord'), { recursive: true })
  writeFileSync(join(dir, '.vord', 'generated.json'), JSON.stringify({ files: { 'src/main.rs': {} } }))
  await assert.rejects(before(hooks, 'apply_patch', { patchText: '*** Begin Patch\n*** Delete File: src/main.rs\n*** End Patch' }), /generated code/)
  await before(hooks, 'apply_patch', { patchText: '*** Begin Patch\n*** Delete File: notes.md\n*** End Patch' })
})

test('the baseline is recorded once, before the first request', async () => {
  const { hooks, dir, calls } = await mount(undefined)
  await hooks['chat.message']({ sessionID: 'ses_1' }, {})
  await hooks['chat.message']({ sessionID: 'ses_1' }, {})
  const baselines = calls().filter(argv => argv[1] === 'baseline')
  assert.equal(baselines.length, 1)
  assert.equal(baselines[0][baselines[0].indexOf('--out') + 1], join(dir, '.vord', 'sessions', 'ses_1.baseline.json'))
})

test('subagent sessions get no baseline of their own', async () => {
  const { hooks, calls } = await mount(undefined)
  await hooks.event({ event: { type: 'session.created', properties: { info: { id: 'child', parentID: 'root' } } } })
  await hooks['chat.message']({ sessionID: 'child' }, {})
  assert.equal(calls().length, 0)
})

test('an idle session with new findings is sent back with the objection', async () => {
  const { hooks, client } = await mount(undefined)
  await hooks['chat.message']({ sessionID: 's1' }, {})
  process.env.FAKE_VORD_DONE = JSON.stringify({ done: false, reason: '1 new finding: python:subprocess-shell-true' })
  await hooks.event({ event: { type: 'session.idle', properties: { sessionID: 's1' } } })
  assert.equal(client.prompts.length, 1)
  assert.equal(client.prompts[0].path.id, 's1')
  assert.match(client.prompts[0].body.parts[0].text, /python:subprocess-shell-true/)
})

test('an idle session vord agrees with is left alone', async () => {
  const { hooks, client } = await mount(undefined)
  await hooks['chat.message']({ sessionID: 's1' }, {})
  await hooks.event({ event: { type: 'session.idle', properties: { sessionID: 's1' } } })
  assert.equal(client.prompts.length, 0)
})

test('the done gate yields after maxStopContinuations in a row', async () => {
  const { hooks, client } = await mount(undefined, { maxStopContinuations: 2 })
  await hooks['chat.message']({ sessionID: 's1' }, {})
  process.env.FAKE_VORD_DONE = JSON.stringify({ done: false, reason: 'still there' })
  for (let i = 0; i < 3; i++) {
    await hooks.event({ event: { type: 'session.idle', properties: { sessionID: 's1' } } })
    // vord's own objection arrives as the next user message and keeps the streak.
    await hooks['chat.message']({ sessionID: 's1' }, {})
  }
  assert.equal(client.prompts.length, 2)
  assert.ok(client.logs.some(entry => /yielded after 2/.test(entry.message)))
})

test('a person writing resets the streak', async () => {
  const { hooks, client } = await mount(undefined, { maxStopContinuations: 1 })
  await hooks['chat.message']({ sessionID: 's1' }, {})
  process.env.FAKE_VORD_DONE = JSON.stringify({ done: false, reason: 'still there' })
  await hooks.event({ event: { type: 'session.idle', properties: { sessionID: 's1' } } })
  await hooks['chat.message']({ sessionID: 's1' }, {}) // vord's objection
  await hooks['chat.message']({ sessionID: 's1' }, {}) // the person
  await hooks.event({ event: { type: 'session.idle', properties: { sessionID: 's1' } } })
  assert.equal(client.prompts.length, 2)
})

test('pending holes in files the session wrote keep it going', async () => {
  const { hooks, client } = await mount(undefined, { analyzerAsDone: false })
  process.env.FAKE_VORD_HOLES = JSON.stringify([
    { kind: 'fn', file: 'src/lib.rs', name: 'total', line: 4, end_line: 6, reason: 'todo!()' },
    { kind: 'fn', file: 'src/other.rs', name: 'x', line: 1, end_line: 2, reason: 'todo!()' },
  ])
  await after(hooks, 'edit', { filePath: 'src/lib.rs', oldString: 'a', newString: 'b' })
  await hooks.event({ event: { type: 'session.idle', properties: { sessionID: 's1' } } })
  assert.equal(client.prompts.length, 1)
  const text = client.prompts[0].body.parts[0].text
  assert.match(text, /src\/lib\.rs:4 `total`/)
  assert.doesNotMatch(text, /other\.rs/)
})

test('a subagent write counts toward its root session', async () => {
  const { hooks, client } = await mount(undefined, { analyzerAsDone: false })
  process.env.FAKE_VORD_HOLES = JSON.stringify([{ kind: 'fn', file: 'a.rs', name: 'f', line: 1, end_line: 2, reason: 'todo!()' }])
  await hooks.event({ event: { type: 'session.created', properties: { info: { id: 'child', parentID: 'root' } } } })
  await after(hooks, 'write', { filePath: 'a.rs', content: 'x' }, undefined, 'child')
  await hooks.event({ event: { type: 'session.idle', properties: { sessionID: 'child' } } })
  assert.equal(client.prompts.length, 0)
  await hooks.event({ event: { type: 'session.idle', properties: { sessionID: 'root' } } })
  assert.equal(client.prompts.length, 1)
  assert.equal(client.prompts[0].path.id, 'root')
})

test('guidance goes into the system prompt and names opencode tool ids', async () => {
  const { hooks } = await mount(undefined, { guidance: true })
  const output = { system: ['base'] }
  await hooks['experimental.chat.system.transform']({ model: {} }, output)
  assert.equal(output.system.length, 2)
  assert.match(output.system[1], /`vord_vord_kickoff`/)
  assert.match(output.system[1], /ferrum` = Rust/)

  const off = await mount(undefined, { guidance: false })
  const none = { system: [] }
  await off.hooks['experimental.chat.system.transform']({ model: {} }, none)
  assert.equal(none.system.length, 0)
})

test('vord mcp is mounted unless the project already configures it', async () => {
  const { hooks } = await mount(undefined)
  const config = {}
  await hooks.config(config)
  assert.deepEqual(config.mcp.vord, { type: 'local', command: [FAKE_VORD, 'mcp'], enabled: true })

  const mine = { mcp: { vord: { type: 'remote', url: 'https://x' } } }
  await hooks.config(mine)
  assert.equal(mine.mcp.vord.type, 'remote')

  const off = await mount(undefined, { mcp: false })
  const none = {}
  await off.hooks.config(none)
  assert.equal(none.mcp, undefined)
})
