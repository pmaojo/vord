// Against the real `vord` binary: proves the payloads this plugin builds are
// ones `vord hook claude-code` actually judges, not just ones the unit tests'
// fake accepts. Skipped unless VORD_BIN points at a built vord
// (`cargo build -p vord-cli --bin vord`, then VORD_BIN=target/debug/vord).
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { VordPlugin } from '../src/index.js'

const VORD = process.env.VORD_BIN && resolve(process.env.VORD_BIN)
const skip = VORD ? false : 'VORD_BIN not set'

const POLICY = `[agent]
enabled = true
block_at_or_above = "blocker"
blocking_rules = ["python:subprocess-shell-true"]
`

const SHELL_SINK = 'import subprocess\n\ndef deploy(target):\n    subprocess.run("deploy " + target, shell=True)\n'
const SAFE = 'import subprocess\n\ndef deploy(target):\n    subprocess.run(["deploy", target])\n'

async function repo() {
  const dir = mkdtempSync(join(tmpdir(), 'opencode-vord-real-'))
  writeFileSync(join(dir, 'vord-policy.toml'), POLICY)
  const prompts = []
  const client = { app: { log: async () => {} }, session: { promptAsync: async (req) => { prompts.push(req) } } }
  const hooks = await VordPlugin({ client, directory: dir }, { command: VORD, failClosed: true, guidance: false })
  const before = (tool, args) => hooks['tool.execute.before']({ tool, sessionID: 's1', callID: 'c1' }, { args })
  return { dir, hooks, prompts, before }
}

test('vord refuses an opencode write that introduces a shell sink', { skip }, async () => {
  const { before } = await repo()
  await assert.rejects(before('write', { filePath: 'deploy.py', content: SHELL_SINK }), /subprocess-shell-true/)
})

test('vord lets the safe version of the same write through', { skip }, async () => {
  const { before } = await repo()
  await before('write', { filePath: 'deploy.py', content: SAFE })
})

test('vord judges an opencode edit on the finished file', { skip }, async () => {
  const { dir, before } = await repo()
  writeFileSync(join(dir, 'deploy.py'), SAFE)
  await assert.rejects(before('edit', {
    filePath: join(dir, 'deploy.py'),
    oldString: 'subprocess.run(["deploy", target])',
    newString: 'subprocess.run("deploy " + target, shell=True)',
  }), /subprocess-shell-true/)
})

test('vord judges each apply_patch hunk on the finished file', { skip }, async () => {
  const { dir, before } = await repo()
  writeFileSync(join(dir, 'deploy.py'), SAFE)
  const patchText = [
    '*** Begin Patch',
    '*** Update File: deploy.py',
    '@@ def deploy(target):',
    '-    subprocess.run(["deploy", target])',
    '+    subprocess.run("deploy " + target, shell=True)',
    '*** End Patch',
  ].join('\n')
  await assert.rejects(before('apply_patch', { patchText }), /subprocess-shell-true/)
  await assert.rejects(before('apply_patch', { patchText: `*** Begin Patch\n*** Add File: new.py\n${SHELL_SINK.trimEnd().split('\n').map((l) => `+${l}`).join('\n')}\n*** End Patch` }), /subprocess-shell-true/)
})

test('the real analyzer sends an idle session back for a finding it introduced', { skip }, async () => {
  const { dir, hooks, prompts } = await repo()
  // Pre-existing finding: part of the baseline, never counted against the task.
  writeFileSync(join(dir, 'legacy.py'), SHELL_SINK)
  await hooks['chat.message']({ sessionID: 's1' }, {})
  await hooks.event({ event: { type: 'session.idle', properties: { sessionID: 's1' } } })
  assert.equal(prompts.length, 0, 'nothing new: the session may rest')

  // A new sink lands by a route the write gate never saw (a shell command);
  // the analyzer still catches it when the session goes idle.
  writeFileSync(join(dir, 'deploy.py'), SHELL_SINK.replace('target', 'host'))
  await hooks.event({ event: { type: 'session.idle', properties: { sessionID: 's1' } } })
  assert.equal(prompts.length, 1)
  assert.match(prompts[0].body.parts[0].text, /deploy\.py/)
})
