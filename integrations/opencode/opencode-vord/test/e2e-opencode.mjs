#!/usr/bin/env node
// Smoke test through a real opencode: runs `opencode run` with this plugin, a
// scripted OpenAI-compatible model and the real `vord`. Checks the write gate
// (a shell-injection sink written with `write` is refused and never reaches
// disk), the analyzer as the definition of done (the same sink written
// through `bash` gets vord's objection sent back into the session), and that
// the standing guidance and vord's MCP tools reach the model.
//
// Not part of `npm test` (it installs opencode and a provider package). Run:
//
//   cargo build -p vord-cli --bin vord
//   npm install --no-save opencode-ai@1.18.34
//   VORD_BIN=../../../target/debug/vord node test/e2e-opencode.mjs
import { spawn } from 'node:child_process'
import { existsSync, mkdtempSync, writeFileSync } from 'node:fs'
import { createServer } from 'node:http'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const vord = resolve(process.env.VORD_BIN ?? 'vord')
const opencode = process.env.OPENCODE_BIN ?? fileURLToPath(new URL('../node_modules/.bin/opencode', import.meta.url))
const pluginDir = fileURLToPath(new URL('..', import.meta.url))
const policy = '[agent]\nenabled = true\nblock_at_or_above = "blocker"\nblocking_rules = ["python:subprocess-shell-true"]\n'
const sink = 'import subprocess\n\ndef deploy(target):\n    subprocess.run("deploy " + target, shell=True)\n'
const OBJECTION = /subprocess-shell-true|new finding|vord:/

/** One SSE chat-completions stream: either a single tool call or plain text. */
function stream(res, reply) {
  res.writeHead(200, { 'content-type': 'text/event-stream', 'cache-control': 'no-cache' })
  const chunk = (delta, finish = null) => res.write(`data: ${JSON.stringify({
    id: 'chatcmpl-mock', object: 'chat.completion.chunk', created: 0, model: 'mock',
    choices: [{ index: 0, delta, finish_reason: finish }],
  })}\n\n`)
  if (reply.tool) {
    chunk({ role: 'assistant', tool_calls: [{ index: 0, id: `call_${Date.now()}`, type: 'function', function: { name: reply.tool, arguments: JSON.stringify(reply.args) } }] })
    chunk({}, 'tool_calls')
  } else {
    chunk({ role: 'assistant', content: reply.text })
    chunk({}, 'stop')
  }
  res.write('data: [DONE]\n\n')
  res.end()
}

/** A model scripted to make one tool call per fresh user prompt, then say done. */
async function mockModel(toolName, toolArguments) {
  const requests = []
  const server = createServer((req, res) => {
    let body = ''
    req.on('data', (c) => { body += c })
    req.on('end', () => {
      const json = JSON.parse(body || '{}')
      requests.push(json)
      const last = json.messages?.at(-1)
      const lastText = typeof last?.content === 'string' ? last.content : JSON.stringify(last?.content ?? '')
      if (!json.tools?.length) return stream(res, { text: 'Deploy script' }) // title / summary requests
      if (last?.role === 'user' && !OBJECTION.test(lastText)) return stream(res, { tool: toolName, args: toolArguments })
      return stream(res, { text: 'done' })
    })
  })
  await new Promise((r) => server.listen(0, '127.0.0.1', r))
  return { requests, baseURL: `http://127.0.0.1:${server.address().port}/v1`, close: () => new Promise((r) => server.close(r)) }
}

/** Poll `probe` until it returns something truthy. */
async function until(probe, timeoutMs) {
  const deadline = Date.now() + timeoutMs
  for (;;) {
    const value = probe()
    if (value) return value
    if (Date.now() > deadline) throw new Error('timed out')
    await new Promise((r) => setTimeout(r, 200))
  }
}

const userTexts = (requests) => requests.flatMap((r) => r.messages.filter((m) => m.role === 'user').map((m) => typeof m.content === 'string' ? m.content : JSON.stringify(m.content)))

/** Run one task in a fresh repo, headless (`opencode run`) or through `opencode serve`. */
async function scenario(toolName, toolArguments, { serve = false } = {}) {
  const repo = mkdtempSync(join(tmpdir(), 'opencode-vord-e2e-'))
  const home = mkdtempSync(join(tmpdir(), 'opencode-vord-home-'))
  writeFileSync(join(repo, 'vord-policy.toml'), policy)
  const model = await mockModel(toolName, toolArguments)
  writeFileSync(join(repo, 'opencode.json'), JSON.stringify({
    $schema: 'https://opencode.ai/config.json',
    plugin: [[pluginDir, { command: vord }]],
    provider: {
      mock: {
        npm: '@ai-sdk/openai-compatible',
        options: { baseURL: model.baseURL, apiKey: 'mock-key' },
        models: { m: { name: 'mock', tool_call: true } },
      },
    },
    model: 'mock/m',
    small_model: 'mock/m',
    permission: { edit: 'allow', bash: 'allow' },
    share: 'disabled',
    autoupdate: false,
  }, null, 2))
  const env = {
    ...process.env,
    PWD: repo,
    PATH: `${dirname(vord)}:${process.env.PATH}`,
    XDG_CONFIG_HOME: join(home, 'config'),
    XDG_DATA_HOME: join(home, 'data'),
    XDG_STATE_HOME: join(home, 'state'),
    XDG_CACHE_HOME: process.env.XDG_CACHE_HOME ?? join(home, 'cache'),
    OPENCODE_DISABLE_AUTOUPDATE: '1',
  }
  const args = serve ? ['serve', '--print-logs', '--port', '0'] : ['run', '--print-logs', '--model', 'mock/m', 'write the deploy script']
  const child = spawn(opencode, args, { cwd: repo, env, stdio: ['ignore', 'pipe', 'pipe'] })
  const out = { text: '' }
  child.stdout.on('data', (c) => { out.text += c })
  child.stderr.on('data', (c) => { out.text += c })
  const closed = new Promise((r) => child.on('close', r))
  const timer = setTimeout(() => child.kill('SIGKILL'), 240_000)
  try {
    if (serve) {
      // `opencode run` exits as soon as the session goes idle, before the
      // done gate can answer; a server (what the TUI and web UI talk to)
      // keeps the session alive, so the objection is observable there.
      const base = await until(() => /https?:\/\/[\w.:-]+:\d+/.exec(out.text)?.[0], 60_000)
      const session = await (await fetch(`${base}/session`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}' })).json()
      await fetch(`${base}/session/${session.id}/message`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ model: { providerID: 'mock', modelID: 'm' }, parts: [{ type: 'text', text: 'write the deploy script' }] }),
      })
      await until(() => userTexts(model.requests).some((t) => /subprocess-shell-true/.test(t)), 60_000).catch(() => {})
      child.kill('SIGTERM')
    }
    await closed
    return { repo, out, requests: model.requests.filter((r) => r.tools?.length) }
  } finally {
    clearTimeout(timer)
    child.kill('SIGKILL')
    await model.close()
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

const toolResults = (requests) => requests.flatMap((r) => r.messages.filter((m) => m.role === 'tool').map((m) => String(m.content)))
// 1. The write gate: a shell sink written with opencode's `write` tool is
//    refused and never reaches disk; guidance and MCP tools reach the model.
{
  const { repo, out, requests } = await scenario('write', { filePath: 'deploy.py', content: sink })
  const results = toolResults(requests)
  check('vord refused the write inside opencode; deploy.py was never written',
    results.some((r) => /python:subprocess-shell-true/.test(r)) && !existsSync(join(repo, 'deploy.py')),
    JSON.stringify({ results, exists: existsSync(join(repo, 'deploy.py')), out: out.text.slice(-4000) }, null, 2))
  const first = requests[0]
  const system = JSON.stringify(first?.messages?.filter((m) => m.role === 'system') ?? [])
  check('the standing guidance is in the system prompt', /vord_vord_kickoff/.test(system) && /ferrum` = Rust/.test(system), system.slice(0, 2000))
  const tools = (first?.tools ?? []).map((t) => t.function?.name)
  check('vord mcp tools are offered to the model', tools.includes('vord_vord_kickoff'), JSON.stringify(tools))
}

// 2. The analyzer as the definition of done: the same sink smuggled in
//    through `bash`, which the write gate never sees, gets vord's objection
//    sent back into the session once it goes idle.
{
  const command = `printf '%s' '${sink.replace(/'/g, "'\\''")}' > deploy.py`
  const { repo, out, requests } = await scenario('bash', { command, description: 'write deploy script' }, { serve: true })
  const texts = userTexts(requests)
  check('the bash write landed (the write gate does not see it)', existsSync(join(repo, 'deploy.py')), out.text.slice(-3000))
  check('vord sent its objection back into the session',
    texts.some((t) => /subprocess-shell-true/.test(t)),
    JSON.stringify({ texts, out: out.text.slice(-4000) }, null, 2))
}

process.exit(failed ? 1 : 0)
