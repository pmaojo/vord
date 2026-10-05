/**
 * Pure translation from an opencode tool call to the hook payload
 * `vord hook claude-code` already judges. No I/O except reading files for the
 * post-execute re-judgement of an `apply_patch`.
 *
 * opencode's `write`/`edit` take camelCase arguments (`filePath`, `oldString`,
 * `newString`, `replaceAll`); `apply_patch` (used by the GPT family instead of
 * `edit`) carries a whole patch, which is split here into one Claude Code
 * `Write` per added file and one `Edit` per hunk.
 * @module opencode-vord/payload
 */

import { readFileSync } from 'node:fs'
import { isAbsolute, resolve } from 'node:path'

/**
 * @param {string} cwd
 * @param {unknown} path
 * @returns {string | undefined}
 */
function absolute(cwd, path) {
  if (typeof path !== 'string' || path.trim().length === 0) return undefined
  return isAbsolute(path) ? path : resolve(cwd, path.trim())
}

/**
 * @typedef {{ kind: 'add', path: string, content: string }
 *   | { kind: 'update', path: string, moveTo?: string, hunks: Array<{ old: string, new: string }> }
 *   | { kind: 'delete', path: string }} PatchOp
 */

/**
 * Parse opencode's `apply_patch` envelope (`*** Begin Patch` … `*** End
 * Patch`, with `*** Add File:`, `*** Update File:` + optional `*** Move to:`,
 * and `*** Delete File:` sections). Paths are returned as written. Unknown
 * lines are ignored; opencode itself rejects a malformed patch.
 * @param {unknown} text
 * @returns {PatchOp[]}
 */
export function parsePatch(text) {
  if (typeof text !== 'string') return []
  /** @type {PatchOp[]} */
  const ops = []
  /** @type {PatchOp | undefined} */
  let op
  /** @type {{ old: string[], new: string[] } | undefined} */
  let hunk
  const closeHunk = () => {
    if (op?.kind === 'update' && hunk && (hunk.old.length > 0 || hunk.new.length > 0)) {
      op.hunks.push({ old: hunk.old.join('\n'), new: hunk.new.join('\n') })
    }
    hunk = undefined
  }
  /** @type {string[]} */
  let added = []
  const closeOp = () => {
    closeHunk()
    if (op?.kind === 'add') op.content = added.length ? `${added.join('\n')}\n` : ''
    if (op) ops.push(op)
    op = undefined
    added = []
  }
  for (const line of text.split('\n')) {
    let m
    if (line.startsWith('*** Begin Patch') || line.startsWith('*** End Patch')) {
      closeOp()
    } else if ((m = /^\*\*\* Add File: (.+)$/.exec(line))) {
      closeOp()
      op = { kind: 'add', path: m[1].trim(), content: '' }
    } else if ((m = /^\*\*\* Update File: (.+)$/.exec(line))) {
      closeOp()
      op = { kind: 'update', path: m[1].trim(), hunks: [] }
    } else if ((m = /^\*\*\* Delete File: (.+)$/.exec(line))) {
      closeOp()
      op = { kind: 'delete', path: m[1].trim() }
    } else if ((m = /^\*\*\* Move to: (.+)$/.exec(line)) && op?.kind === 'update') {
      op.moveTo = m[1].trim()
    } else if (line.startsWith('*** End of File')) {
      // marker only
    } else if (op?.kind === 'add') {
      if (line.startsWith('+')) added.push(line.slice(1))
    } else if (op?.kind === 'update') {
      if (line.startsWith('@@')) {
        closeHunk()
        hunk = { old: [], new: [] }
        continue
      }
      hunk ??= { old: [], new: [] }
      if (line.startsWith('+')) hunk.new.push(line.slice(1))
      else if (line.startsWith('-')) hunk.old.push(line.slice(1))
      else if (line.startsWith(' ')) {
        hunk.old.push(line.slice(1))
        hunk.new.push(line.slice(1))
      }
    }
  }
  closeOp()
  return ops
}

/**
 * The Claude Code `tool_name`/`tool_input` pairs vord judges before one
 * opencode write runs. Empty for a call vord has no opinion on (reads, MCP
 * tools, …). An `apply_patch` yields one entry per added file and per hunk.
 * @param {string} name - the opencode tool id.
 * @param {any} args - the tool arguments.
 * @param {string} cwd - the directory relative paths resolve against.
 * @returns {Array<{ tool_name: string, tool_input: Record<string, unknown> }>}
 */
export function writeCalls(name, args, cwd) {
  if (args === null || typeof args !== 'object') return []
  switch (name) {
    case 'write': {
      const file_path = absolute(cwd, args.filePath)
      if (!file_path || typeof args.content !== 'string') return []
      return [{ tool_name: 'Write', tool_input: { file_path, content: args.content } }]
    }
    case 'edit': {
      const file_path = absolute(cwd, args.filePath)
      if (!file_path) return []
      return [{
        tool_name: 'Edit',
        tool_input: {
          file_path,
          old_string: args.oldString,
          new_string: args.newString,
          replace_all: args.replaceAll ?? false,
        },
      }]
    }
    case 'apply_patch': {
      const calls = []
      for (const op of parsePatch(args.patchText)) {
        const file_path = absolute(cwd, op.path)
        if (!file_path) continue
        if (op.kind === 'add') {
          calls.push({ tool_name: 'Write', tool_input: { file_path, content: op.content } })
        } else if (op.kind === 'update') {
          for (const hunk of op.hunks) {
            if (hunk.old.length === 0) continue
            calls.push({
              tool_name: 'Edit',
              tool_input: { file_path, old_string: hunk.old, new_string: hunk.new, replace_all: false },
            })
          }
        }
      }
      return calls
    }
    default:
      return []
  }
}

/**
 * Files one write leaves on disk, absolute: what the post-execute
 * re-judgement reads back and what counts as "touched" for the holes gate.
 * @param {string} name
 * @param {any} args
 * @param {string} cwd
 * @returns {string[]}
 */
export function writtenFiles(name, args, cwd) {
  if (args === null || typeof args !== 'object') return []
  if (name === 'write' || name === 'edit') {
    const file = absolute(cwd, args.filePath)
    return file ? [file] : []
  }
  if (name === 'apply_patch') {
    return parsePatch(args.patchText)
      .filter((op) => op.kind !== 'delete')
      .map((op) => absolute(cwd, op.kind === 'update' && op.moveTo ? op.moveTo : op.path))
      .filter((file) => file !== undefined)
  }
  return []
}

/**
 * Files an `apply_patch` deletes, absolute.
 * @param {string} name
 * @param {any} args
 * @param {string} cwd
 * @returns {string[]}
 */
export function deletedFiles(name, args, cwd) {
  if (name !== 'apply_patch' || args === null || typeof args !== 'object') return []
  return parsePatch(args.patchText)
    .flatMap((op) => {
      if (op.kind === 'delete') return [op.path]
      if (op.kind === 'update' && op.moveTo) return [op.path]
      return []
    })
    .map((path) => absolute(cwd, path))
    .filter((file) => file !== undefined)
}

/**
 * The post-execute `Write` payload for a file as it now is on disk, or
 * `undefined` when it cannot be read.
 * @param {string} file
 * @returns {{ tool_name: string, tool_input: Record<string, unknown> } | undefined}
 */
export function landedWrite(file) {
  try {
    return { tool_name: 'Write', tool_input: { file_path: file, content: readFileSync(file, 'utf8') } }
  } catch {
    return undefined
  }
}

/** opencode's shell tool id. */
export const SHELL_TOOL = 'bash'

/**
 * @param {string} event
 * @param {string} cwd
 * @param {string} tool_name
 * @param {Record<string, unknown>} tool_input
 * @param {unknown} [tool_response]
 * @returns {Record<string, unknown>}
 */
export function hookPayload(event, cwd, tool_name, tool_input, tool_response) {
  return {
    hook_event_name: event,
    cwd,
    tool_name,
    tool_input,
    ...tool_response !== undefined ? { tool_response } : {},
  }
}

/**
 * The `tool_response` vord reads a shell exit code from. opencode's bash
 * tool reports it as `metadata.exit` (`null` when the command was aborted or
 * timed out, which is reported as exit 1 so an unfinished test run cannot
 * clear the ledger).
 * @param {{ metadata?: any }} output
 * @returns {{ exit_code: number }}
 */
export function shellResponse(output) {
  const code = output?.metadata?.exit
  return { exit_code: typeof code === 'number' ? code : 1 }
}
