#!/usr/bin/env node
// Smoke test through a real DeepSeek Harness: boots the published `dsh`
// headless app with the dsh-vord bundle, a scripted model, and the real
// `vord`. Checks the write gate (a shell-injection sink is denied and never
// reaches disk) and the analyzer as the definition of done (the same sink
// written through `bash` keeps the turn open).
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
const policy = '[agent]\nenabled = true\nblock_at_or_above = "blocker"\nblocking_rules = ["python:subprocess-shell-true"]\n'
const sink = 'import subprocess\n\ndef deploy(target):\n    subprocess.run("deploy " + target, shell=True)\n'

/** Run one headless task in a fresh repo against a model scripted to make one tool call. */
async function scenario(toolName, toolArguments) {
  const repo = mkdtempSync(join(tmpdir(), 'dsh-vord-boot-'))
  writeFileSync(join(repo, 'vord-policy.toml'), policy)
  const server = await startMockLlmServer({
    sequence: ['tool_call_success', 'success'],
    repeatLast: true,
    toolName,
    toolArguments: JSON.stringify(toolArguments),
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
    }).catch(error => error)
    const events = String(run.stdout ?? '').trim().split('\n').filter(Boolean).map(line => JSON.parse(line))
    const requests = server.requests.map(r => JSON.stringify(r))
    return { repo, events, requests }
  } finally {
    await server.close()
  }
}

let failed = false
function check(name, ok, detail) {
  console.log(`${ok ? 'PASS' : 'FAIL'}: ${name}`)
  if (!ok) {
    failed = true
    console.log(detail)
  }
}

// 1. The write gate: a shell sink written with dsh's `write` tool is denied
//    and never reaches disk.
{
  const { repo, events } = await scenario('write', { file_path: 'deploy.py', content: sink })
  const denied = events.find(e => e.status === 'error' && typeof e.result === 'string')
  check('vord denied the write inside dsh; deploy.py was never written',
    /python:subprocess-shell-true/.test(denied?.result ?? '') && !existsSync(join(repo, 'deploy.py')),
    JSON.stringify(events.filter(e => e.type !== 'status')))
}

// 2. The analyzer as the definition of done: the same sink smuggled in through
//    `bash`, which the write gate never sees, still keeps the turn open — the
//    model is sent back with the analyzer's objection.
{
  const command = `printf '%s' '${sink.replaceAll("'", "'\\''")}' > deploy.py`
  const { requests } = await scenario('bash', { command, description: 'Write the deploy script' })
  check('the analyzer held the turn open after a bash-written sink',
    requests.some(r => r.includes('introduced') && r.includes('deploy.py')),
    `${requests.length} requests; last: ${requests.at(-1)?.slice(-800)}`)
}

process.exitCode = failed ? 1 : 0
