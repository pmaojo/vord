import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { applyInsert, shellResponse, writeCall } from '../src/payload.js'

test('write maps to Write with an absolute path', () => {
  assert.deepEqual(writeCall('write', { file_path: 'src/a.py', content: 'x' }, '/repo'), {
    tool_name: 'Write', tool_input: { file_path: '/repo/src/a.py', content: 'x' },
  })
})

test('edit keeps the search/replace pair and defaults replace_all', () => {
  assert.deepEqual(writeCall('edit', { file_path: '/abs/a.py', old_string: 'a', new_string: 'b' }, '/repo'), {
    tool_name: 'Edit', tool_input: { file_path: '/abs/a.py', old_string: 'a', new_string: 'b', replace_all: false },
  })
})

test('str_replace_editor create and str_replace map to Write and Edit', () => {
  assert.equal(writeCall('str_replace_editor', { command: 'create', path: 'a.py', file_text: 'x' }, '/r').tool_name, 'Write')
  assert.deepEqual(writeCall('str_replace_editor', { command: 'str_replace', path: 'a.py', old_str: 'x' }, '/r').tool_input, {
    file_path: '/r/a.py', old_string: 'x', new_string: '', replace_all: false,
  })
})

test('str_replace_editor insert is judged on the finished file', () => {
  const dir = mkdtempSync(join(tmpdir(), 'dsh-vord-'))
  writeFileSync(join(dir, 'a.py'), 'one\ntwo\n')
  const call = writeCall('str_replace_editor', { command: 'insert', path: 'a.py', insert_line: 1, new_str: 'mid' }, dir)
  assert.deepEqual(call, { tool_name: 'Write', tool_input: { file_path: join(dir, 'a.py'), content: 'one\nmid\ntwo\n' } })
  assert.equal(applyInsert(join(dir, 'a.py'), 9, 'x'), undefined, 'out of range is not guessed at')
})

test('reads, views and unknown tools are not judged', () => {
  assert.equal(writeCall('read', { file_path: 'a' }, '/r'), undefined)
  assert.equal(writeCall('str_replace_editor', { command: 'view', path: 'a' }, '/r'), undefined)
  assert.equal(writeCall('mcp__x__write', { file_path: 'a', content: 'x' }, '/r'), undefined)
  assert.equal(writeCall('write', { file_path: '  ', content: 'x' }, '/r'), undefined)
})

test('a shell call that never finished cannot count as a passing test run', () => {
  assert.deepEqual(shellResponse({ isError: false, value: { exitCode: 0 } }), { exit_code: 0 })
  assert.deepEqual(shellResponse({ isError: false, value: { exitCode: null } }), { exit_code: 1 })
  assert.deepEqual(shellResponse({ isError: true }), { exit_code: 1 })
})
