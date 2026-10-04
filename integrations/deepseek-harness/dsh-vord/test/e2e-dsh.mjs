#!/usr/bin/env node
// Smoke test through a real DeepSeek Harness: boots the published `dsh`
// headless app with the dsh-vord bundle, a scripted model that tries to write
// a shell-injection sink, and the real `vord`. Passes when the write is denied
// and the file never reaches disk.
//
// Not part of `npm test` (it installs dsh and boots a profile). Run it with:
//
//   cargo build -p vord-cli --bin vord
//   npm install --no-save @deepseek-ai/dsh@0.2.0-rc.2 @deepseek-ai/dsh-llm-mock-server@0.2.0-rc.2
//   export DSH_HOME=$(mktemp -d)
//   npx dsh vord --from-default-profile headless --dump-config > /dev/null
//   npx dsh plugin --profile vord add "file:$PWD"
//   VORD_BIN=../../../target/debug/vord node test/e2e-dsh.mjs
import { startMockLlmServer } from '@deepseek-ai/dsh-llm-mock-server'
import { execFile } from 'node:child_process'
import { existsSync, mkdtempSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { promisify } from 'node:util'

const vord = resolve(process.env.VORD_BIN ?? 'vord')
const dsh = fileURLToPath(new URL('../node_modules/.bin/dsh', import.meta.url))
const repo = mkdtempSync(join(tmpdir(), 'dsh-vord-boot-'))
writeFileSync(join(repo, 'vord-policy.toml'), '[agent]\nenabled = true\nblock_at_or_above = "blocker"\nblocking_rules = ["python:subprocess-shell-true"]\n')
const sink = 'import subprocess\n\ndef deploy(target):\n    subprocess.run("deploy " + target, shell=True)\n'

const server = await startMockLlmServer({
  sequence: ['tool_call_success', 'success'],
  repeatLast: true,
  toolName: 'write',
  toolArguments: JSON.stringify({ file_path: 'deploy.py', content: sink }),
  successText: 'done',
})
try {
  const run = await promisify(execFile)(dsh, ['vord', '--json', 'write the deploy script'], {
    cwd: repo,
    timeout: 180_000,
    env: {
      ...process.env,
      DEEPSEEK_BASE_URL: `${server.baseURL}/v1`,
      DEEPSEEK_API_KEY: 'mock-key',
      PATH: `${dirname(vord)}:${process.env.PATH}`,
    },
  })
  const events = run.stdout.trim().split('\n').map(line => JSON.parse(line))
  const denied = events.find(e => e.type === 'tool_result' || (e.status === 'error' && typeof e.result === 'string'))
  const ok = denied?.status === 'error'
    && /python:subprocess-shell-true/.test(denied.result)
    && !existsSync(join(repo, 'deploy.py'))
  console.log(ok ? 'PASS: vord denied the write inside dsh; deploy.py was never written' : `FAIL: ${JSON.stringify(denied)}`)
  process.exitCode = ok ? 0 : 1
} finally {
  await server.close()
}
