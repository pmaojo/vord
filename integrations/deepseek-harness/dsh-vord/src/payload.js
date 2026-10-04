/**
 * Pure translation from a DeepSeek Harness tool call to the hook payload
 * `vord hook claude-code` already judges. No I/O except reading the current
 * file for `str_replace_editor insert`, which has no search/replace pair vord
 * could apply itself.
 *
 * dsh's own `write`/`edit` tools take the same argument names Claude Code's
 * `Write`/`Edit` do (`file_path`, `content`, `old_string`, `new_string`,
 * `replace_all`), so most of this is renaming the tool, not reshaping input.
 * @module dsh-vord/payload
 */

import { readFileSync } from 'node:fs'
import { isAbsolute, resolve } from 'node:path'

/**
 * The repository root a call is judged against: the agent's session
 * workspace, falling back to the process's working directory for a direct
 * tool call with no agent.
 * @param {{ agent?: { session?: { header?: { cwd?: string } } } }} exec
 * @returns {string}
 */
export function sessionCwd(exec) {
  return exec.agent?.session?.header?.cwd ?? process.cwd()
}

/**
 * @param {string} cwd
 * @param {unknown} path
 * @returns {string | undefined}
 */
function absolute(cwd, path) {
  if (typeof path !== 'string' || path.trim().length === 0) return undefined
  return isAbsolute(path) ? path : resolve(cwd, path)
}

/**
 * Apply `str_replace_editor`'s `insert`: `new_str` goes after line
 * `insert_line` (0 = top of file), exactly as the tool itself splits lines.
 * Returns `undefined` when the file cannot be read or the line is out of
 * range — the tool will refuse that call anyway, so nothing is judged.
 * @param {string} file
 * @param {number} insertLine
 * @param {string} newStr
 * @returns {string | undefined}
 */
export function applyInsert(file, insertLine, newStr) {
  let current
  try {
    current = readFileSync(file, 'utf8')
  } catch {
    return undefined
  }
  const lines = current.split('\n')
  if (!Number.isInteger(insertLine) || insertLine < 0 || insertLine > lines.length) return undefined
  return [...lines.slice(0, insertLine), ...newStr.split('\n'), ...lines.slice(insertLine)].join('\n')
}

/**
 * The Claude Code `tool_name`/`tool_input` pair vord judges for one dsh
 * write, or `undefined` for a call vord has no opinion on (reads, `view`,
 * `undo_edit`, MCP tools, …).
 * @param {string} name - the dsh tool name.
 * @param {any} args - the parsed tool arguments.
 * @param {string} cwd - the session workspace relative paths resolve against.
 * @returns {{ tool_name: string, tool_input: Record<string, unknown> } | undefined}
 */
export function writeCall(name, args, cwd) {
  if (args === null || typeof args !== 'object') return undefined
  switch (name) {
    case 'write': {
      const file_path = absolute(cwd, args.file_path)
      if (!file_path || typeof args.content !== 'string') return undefined
      return { tool_name: 'Write', tool_input: { file_path, content: args.content } }
    }
    case 'edit': {
      const file_path = absolute(cwd, args.file_path)
      if (!file_path) return undefined
      return {
        tool_name: 'Edit',
        tool_input: {
          file_path,
          old_string: args.old_string,
          new_string: args.new_string,
          replace_all: args.replace_all ?? false,
        },
      }
    }
    case 'str_replace_editor': {
      const file_path = absolute(cwd, args.path)
      if (!file_path) return undefined
      switch (args.command) {
        case 'create':
          return typeof args.file_text === 'string'
            ? { tool_name: 'Write', tool_input: { file_path, content: args.file_text } }
            : undefined
        case 'str_replace':
          return {
            tool_name: 'Edit',
            tool_input: { file_path, old_string: args.old_str, new_string: args.new_str ?? '', replace_all: false },
          }
        case 'insert': {
          if (typeof args.new_str !== 'string') return undefined
          const content = applyInsert(file_path, args.insert_line, args.new_str)
          return content === undefined
            ? undefined
            : { tool_name: 'Write', tool_input: { file_path, content } }
        }
        default:
          return undefined
      }
    }
    default:
      return undefined
  }
}

/**
 * dsh's shell tool, whose command line can clear vord's test-evidence ledger.
 * `dsh-tool-bash` and `dsh-tool-bash-persistent` both register as `bash`.
 */
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
 * The `tool_response` vord reads a shell exit code from. dsh's bash tool
 * returns `{ exitCode }` as its canonical value; a failed call (thrown,
 * denied, timed out) carries no value and is reported as exit 1 so a test
 * run that never finished cannot clear the ledger.
 * @param {{ isError: boolean, value?: any }} result
 * @returns {{ exit_code: number }}
 */
export function shellResponse(result) {
  if (result.isError) return { exit_code: 1 }
  const code = result.value?.exitCode
  return { exit_code: typeof code === 'number' ? code : 1 }
}
