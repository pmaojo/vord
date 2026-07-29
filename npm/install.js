#!/usr/bin/env node
// Downloads the yunq binary matching this platform from the GitHub release
// whose tag matches this package's version, and verifies its published
// SHA-256.
//
// Runs as a postinstall step, so it must degrade honestly: a failure here
// leaves a clear message and a non-zero exit rather than a silently missing
// binary that only surfaces at first use.

const fs = require('node:fs');
const path = require('node:path');
const https = require('node:https');
const crypto = require('node:crypto');

const REPO = 'pmaojo/yunq';
const version = require('./package.json').version;

const TARGETS = {
  'linux-x64': 'x86_64-unknown-linux-musl',
  'linux-arm64': 'aarch64-unknown-linux-musl',
  'darwin-x64': 'x86_64-apple-darwin',
  'darwin-arm64': 'aarch64-apple-darwin',
  'win32-x64': 'x86_64-pc-windows-msvc',
};

function fail(msg) {
  console.error(`\nyunq: ${msg}`);
  console.error(`Install manually: https://github.com/${REPO}/releases\n`);
  process.exit(1);
}

// Follows redirects, which the GitHub release download endpoint always issues.
function get(url, redirectsLeft = 10) {
  return new Promise((resolve, reject) => {
    https
      .get(url, { headers: { 'User-Agent': 'yunq-npm-installer' } }, (res) => {
        if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
          res.resume();
          if (redirectsLeft === 0) return reject(new Error('too many redirects'));
          return resolve(get(res.headers.location, redirectsLeft - 1));
        }
        if (res.statusCode !== 200) {
          res.resume();
          return reject(new Error(`HTTP ${res.statusCode} for ${url}`));
        }
        const chunks = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () => resolve(Buffer.concat(chunks)));
        res.on('error', reject);
      })
      .on('error', reject);
  });
}

async function main() {
  const key = `${process.platform}-${process.arch}`;
  const target = TARGETS[key];
  if (!target) fail(`unsupported platform ${key}`);

  const ext = process.platform === 'win32' ? '.exe' : '';
  const asset = `yunq-${target}${ext}`;
  const base = `https://github.com/${REPO}/releases/download/v${version}`;

  console.log(`yunq: downloading ${asset} (v${version})`);
  let binary;
  try {
    binary = await get(`${base}/${asset}`);
  } catch (e) {
    fail(`download failed — ${e.message}`);
  }

  // A checksum we could not fetch is reported, never silently treated as a
  // pass: "unverified" and "verified" must not look the same in the log.
  try {
    const sums = (await get(`${base}/${asset}.sha256`)).toString('utf8');
    const expected = sums.trim().split(/\s+/)[0];
    const actual = crypto.createHash('sha256').update(binary).digest('hex');
    if (expected !== actual) fail(`checksum mismatch (expected ${expected}, got ${actual})`);
    console.log('yunq: checksum verified');
  } catch (e) {
    if (String(e.message).includes('checksum mismatch')) throw e;
    console.warn(`yunq: warning — no published checksum for ${asset}, not verified`);
  }

  const dir = path.join(__dirname, 'bin');
  fs.mkdirSync(dir, { recursive: true });
  const dest = path.join(dir, `yunq${ext}`);
  fs.writeFileSync(dest, binary, { mode: 0o755 });
  console.log(`yunq: installed ${dest}`);
}

main().catch((e) => fail(e.message));
