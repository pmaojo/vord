#!/usr/bin/env node
// Stand-in for the vord CLI.
// - `hook claude-code`: appends the stdin payload to $FAKE_VORD_LOG and prints
//   $FAKE_VORD_OUTPUT (empty = silent).
// - `agent baseline --out F`: writes an empty baseline to F, logs the call.
// - `agent done --json`: prints $FAKE_VORD_DONE (default: done) and exits 3
//   when it says not done, as vord does.
import { appendFileSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { dirname } from 'node:path'

const args = process.argv.slice(2)
const log = (entry) => {
  if (process.env.FAKE_VORD_LOG) appendFileSync(process.env.FAKE_VORD_LOG, JSON.stringify(entry) + '\n')
}
if (process.env.FAKE_VORD_EXIT) process.exit(Number(process.env.FAKE_VORD_EXIT))

if (args[0] === 'agent' && args[1] === 'baseline') {
  const out = args[args.indexOf('--out') + 1]
  mkdirSync(dirname(out), { recursive: true })
  writeFileSync(out, '[]')
  log({ argv: args })
} else if (args[0] === 'agent' && args[1] === 'done') {
  log({ argv: args })
  const verdict = process.env.FAKE_VORD_DONE ?? JSON.stringify({ done: true, reason: 'the analyzer agrees the task is complete' })
  process.stdout.write(verdict)
  process.exit(JSON.parse(verdict).done ? 0 : 3)
} else {
  const payload = readFileSync(0, 'utf8')
  log(JSON.parse(payload))
  process.stdout.write(process.env.FAKE_VORD_OUTPUT ?? '')
}
