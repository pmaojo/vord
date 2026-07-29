#!/usr/bin/env node
// Thin launcher: forwards argv to the downloaded native binary and mirrors
// its exit code, so `npx yunq scan --enforce-gate` fails a CI job exactly as
// the native binary would.

const path = require('node:path');
const fs = require('node:fs');
const { spawnSync } = require('node:child_process');

const ext = process.platform === 'win32' ? '.exe' : '';
const bin = path.join(__dirname, `yunq${ext}`);

if (!fs.existsSync(bin)) {
  console.error('yunq: the native binary is missing — the postinstall step did not complete.');
  console.error('Re-run `npm rebuild yunq`, or install from https://github.com/pmaojo/yunq/releases');
  process.exit(1);
}

const res = spawnSync(bin, process.argv.slice(2), { stdio: 'inherit' });
if (res.error) {
  console.error(`yunq: ${res.error.message}`);
  process.exit(1);
}
// A signal death must not be reported as exit 0.
process.exit(res.status === null ? 1 : res.status);
