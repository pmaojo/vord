#!/usr/bin/env node
// Stand-in for `vord hook claude-code`: appends the payload it received to
// $FAKE_VORD_LOG and prints $FAKE_VORD_OUTPUT (empty = silent).
import { appendFileSync, readFileSync } from 'node:fs'
const payload = readFileSync(0, 'utf8')
if (process.env.FAKE_VORD_LOG) appendFileSync(process.env.FAKE_VORD_LOG, payload + '\n')
if (process.env.FAKE_VORD_EXIT) process.exit(Number(process.env.FAKE_VORD_EXIT))
process.stdout.write(process.env.FAKE_VORD_OUTPUT ?? '')
