/**
 * Harness-independent pieces of vord's guardrail, shared in spirit with
 * dsh-vord: the standing guidance, the per-session baseline path, and the
 * generated-code deletion guard.
 * @module opencode-vord/guard
 */

import { existsSync, readFileSync } from 'node:fs'
import { dirname, join, relative, resolve } from 'node:path'

/**
 * Standing guidance for the model: scaffold with vord instead of hand-writing
 * boilerplate. `tool` turns a vord MCP tool name into the name opencode
 * exposes it under (`<server>_<tool>`).
 * @param {(name: string) => string} tool
 */
export function defaultGuidance(tool) {
  return [
    'vord is mounted in this session. Follow these rules for new projects and features:',
    `- Scaffold with the \`${tool('vord_kickoff')}\` MCP tool instead of hand-writing boilerplate. Call it with \`plan\` first to preview, then generate.`,
    '- Pick the engine by the backend language the user asked for: `ferrum` = Rust, `kthulu` = Go, `wasp` = TypeScript full-stack, `copier` = any template (e.g. Python/FastAPI), `openapi` = generate from an OpenAPI spec. Never pick an engine for a different language.',
    `- Never delete or hand-rewrite generated output (no \`rm -rf\` on the generated project). To change it, edit the blueprint and regenerate; fill the marked holes through \`${tool('vord_holes')}\`.`,
    `- Describe the app with the \`entities\` argument of \`${tool('vord_kickoff')}\` (e.g. {"todo": {"title": "string", "done": "bool"}}) instead of writing a blueprint, and pass \`check_build\` so the result is built before you start.`,
    `- If generated code is wrong (imports types that do not exist, a handler is missing, a model lacks a column), do NOT work around it and do not edit the file: call \`${tool('vord_report_generator_defect')}\`, then fix the blueprint or the engine template and regenerate. \`${tool('vord_done')}\` stays not-done while a defect is open.`,
    `- Generated files you do not need (a duplicate frontend, bundled templates) are removed with \`${tool('vord_prune')}\`, not \`rm\`: it records the removal and the write gate stops guarding them.`,
    '- Open the generated project directory as the workspace for all further work.',
  ].join('\n')
}

/**
 * Where a session's baseline lives: one file per session, so concurrent or
 * resumed sessions in one workspace never compare against each other's.
 * @param {string} cwd
 * @param {string} sessionId
 */
export function baselinePath(cwd, sessionId) {
  return join(cwd, '.vord', 'sessions', `${sessionId.replace(/[^A-Za-z0-9_.-]/g, '_')}.baseline.json`)
}

/**
 * The generated-code manifest that governs `path`: the nearest
 * `.vord/generated.json` in `path` or one of its ancestors.
 * @param {string} path
 * @returns {{ root: string, files: string[] } | undefined}
 */
function governingManifest(path) {
  for (let dir = path; ; dir = dirname(dir)) {
    const file = join(dir, '.vord', 'generated.json')
    if (existsSync(file)) {
      try {
        const parsed = JSON.parse(readFileSync(file, 'utf8'))
        // Seeds (one-pass scaffolds) are editable and deletable; only regenerable files are guarded.
        const entries = Object.entries(parsed?.files ?? {})
        return { root: dir, files: entries.filter(([, v]) => v?.kind !== 'seed').map(([k]) => k) }
      } catch {
        return { root: dir, files: [] }
      }
    }
    if (dirname(dir) === dir) return undefined
  }
}

const DELETE_REASON = (target) =>
  `vord: ${target} holds generated code recorded in .vord/generated.json. Do not delete or hand-rewrite scaffolded output. To drop files that are not needed (a duplicate frontend, bundled templates) call the vord_prune tool; to change what is generated, change the blueprint and run the engine's regenerate command (or vord kickoff with the right engine: ferrum = Rust, kthulu = Go, wasp = TypeScript).`

/**
 * Does removing `path` remove generated code: the project that holds the
 * manifest, a directory under it that holds generated files, or one
 * generated file? Returns the denial reason, or `undefined`.
 * @param {string} path - absolute.
 * @param {string} [shown] - how to name it in the reason.
 */
export function deletesGenerated(path, shown = path) {
  const manifest = governingManifest(path)
  if (!manifest) return undefined
  const rel = relative(manifest.root, path).split('\\').join('/')
  const hit = rel === '' || manifest.files.some((f) => f === rel || f.startsWith(`${rel}/`))
  return hit ? DELETE_REASON(shown) : undefined
}

/**
 * A recursive `rm` that would remove generated code recorded in a vord
 * manifest. Other deletions inside a generated project (`node_modules`,
 * build output) pass. Returns the denial reason, or `undefined`.
 * @param {unknown} commandLine
 * @param {string} cwd
 * @returns {string | undefined}
 */
export function deletesGeneratedProject(commandLine, cwd) {
  if (typeof commandLine !== 'string') return undefined
  for (const segment of commandLine.split(/&&|\|\||;|\|/)) {
    const words = segment.trim().split(/\s+/)
    if (words[0] !== 'rm') continue
    const flags = words.filter((w) => w.startsWith('-') && !w.startsWith('--'))
    const recursive = flags.some((f) => /[rR]/.test(f)) || words.includes('--recursive')
    if (!recursive) continue
    for (const target of words.slice(1).filter((w) => !w.startsWith('-'))) {
      // `dir/*` removes what is inside `dir`: judge the directory itself.
      const literal = target.replace(/^["']|["']$/g, '').replace(/\/?[^/]*[*?[].*$/, '') || '.'
      const reason = deletesGenerated(resolve(cwd, literal), target)
      if (reason) return reason
    }
  }
  return undefined
}
