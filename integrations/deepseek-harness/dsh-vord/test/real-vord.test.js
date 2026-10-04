// End-to-end against the real `vord` binary: proves the payloads this plugin
// builds are ones `vord hook claude-code` actually judges, not just ones the
// unit tests' fake accepts. Skipped unless VORD_BIN points at a built vord
// (`cargo build -p vord-cli --bin vord`, then VORD_BIN=target/debug/vord).
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { apply } from '../src/index.js'
import { allow, execution, fakeAgent, fakeContext } from './helpers.js'

const VORD = process.env.VORD_BIN
const skip = VORD ? false : 'VORD_BIN not set'

const POLICY = `[agent]
enabled = true
block_at_or_above = "blocker"
blocking_rules = ["python:subprocess-shell-true"]
`

const SHELL_SINK = 'import subprocess\n\ndef deploy(target):\n    subprocess.run("deploy " + target, shell=True)\n'
const SAFE = 'import subprocess\n\ndef deploy(target):\n    subprocess.run(["deploy", target])\n'

function repo() {
  const dir = mkdtempSync(join(tmpdir(), 'dsh-vord-e2e-'))
  writeFileSync(join(dir, 'vord-policy.toml'), POLICY)
  const ctx = fakeContext()
  apply(ctx, { command: VORD, failClosed: true })
  return { ctx, agent: fakeAgent(dir) }
}

test('vord denies a dsh write that introduces a shell sink', { skip }, async () => {
  const { ctx, agent } = repo()
  const decision = await ctx.fire('tools/pre-execute', execution('write', { file_path: 'deploy.py', content: SHELL_SINK }, agent), allow)
  assert.equal(decision.kind, 'deny', JSON.stringify(decision))
  assert.match(decision.reason, /subprocess-shell-true/)
})

test('vord lets the safe version of the same write through', { skip }, async () => {
  const { ctx, agent } = repo()
  const decision = await ctx.fire('tools/pre-execute', execution('write', { file_path: 'deploy.py', content: SAFE }, agent), allow)
  assert.deepEqual(decision, { kind: 'allow' })
})

test('vord judges a str_replace_editor edit on the finished file', { skip }, async () => {
  const { ctx, agent } = repo()
  writeFileSync(join(agent.session.header.cwd, 'deploy.py'), SAFE)
  const decision = await ctx.fire('tools/pre-execute', execution('str_replace_editor', {
    command: 'str_replace', path: 'deploy.py',
    old_str: 'subprocess.run(["deploy", target])', new_str: 'subprocess.run("deploy " + target, shell=True)',
  }, agent), allow)
  assert.equal(decision.kind, 'deny', JSON.stringify(decision))
})
