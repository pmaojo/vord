# vord Guardrail on DeepSeek Harness

[DeepSeek Harness](https://github.com/deepseek-ai/deepseek-harness) (`dsh`)
ships an official `@deepseek-ai/dsh-hooks-claude-code` bridge plugin whose
job is to run an existing Claude Code `hooks.json` — the same
`PreToolUse`/`PostToolUse` shell-command hooks `vord hook install` already
writes — on the harness's own interception points. No new vord code is
needed: this directory just wires the two together.

## What was verified, and how

This wasn't taken on the bridge's README alone. The published packages were
pulled from npm and diffed against `bin/cli/src/hook.rs` directly:

- `@deepseek-ai/dsh-hook-protocol`'s codec (`parseHookOutput`) parses
  `hookSpecificOutput.permissionDecision` (`allow`/`deny`/`ask`) on
  `PreToolUse` and a top-level `{"decision": "block", "reason": ...}` on
  `PostToolUse` — byte-for-byte the same shape [`claude_code_output`
  in `bin/cli/src/hook.rs`](../../bin/cli/src/hook.rs) emits.
- The bridge's mapping table sends a `PreToolUse` `deny` to
  `PreToolDecision.deny` and a `PostToolUse` `deny` to a blocked result with
  feedback — the two outcomes vord's guardrail actually uses (it never emits
  `allow`; see the "Failing open" section of the root README for why).

## The one gotcha: tool names are not capitalized here

Claude Code's built-in tools are `Edit`/`Write`. DeepSeek Harness's own
filesystem tools (`@deepseek-ai/dsh-tool-fs`) are named `edit`/`write` —
lowercase, to match its own tool-schema convention. The bridge's matcher is
an **exact, case-sensitive** string match against whichever tool name fired
(`matchesMatcher` in `dsh-hook-protocol`, `"claude"` dialect: a bare
word/pipe pattern like `Edit|Write` is a literal set, not a
case-insensitive regex).

`vord hook install`'s own `.claude/settings.json` uses `Edit|Write`, which
is correct for Claude Code but silently never fires against dsh's native
`write`/`edit` tools — a guardrail that looks installed but never triggers
is worse than no guardrail. That's why [`hooks/hooks.json`](hooks/hooks.json)
in this directory matches `Edit|Write|edit|write` instead: it covers dsh's
own tools *and* the Claude Code/Codex tool names dsh reports when a session
delegates to a real Claude Code or Codex subagent.

## Setup

1. `vord` on `PATH` (see the repository root README's "Install" section),
   and a `vord-policy.toml` in the repository (`vord hook install` writes a
   starter one, or use the built-in default).
2. Install the bridge: `npm install -g @deepseek-ai/dsh-hooks-claude-code`.
3. Mount it in your `dsh` preset/`cordis.yml` — see [`cordis.yml`](cordis.yml)
   in this directory for the exact entry, pointed at
   [`hooks/hooks.json`](hooks/hooks.json).

## Status

DeepSeek Harness is a developer preview (`0.1.0-rc.x` at the time this was
written) with explicit breaking-change warnings. The protocol pieces this
integration depends on (`dsh-hook-protocol`'s codec and matcher,
`dsh-hooks-claude-code`'s decision mapping) are marked "Product — stable
API" in the harness's own package classification, but re-verify after a
harness upgrade rather than assuming it holds.

vord's own MCP server (`vord mcp`, documented in the root README's
"`vord mcp`" section) also works as a tool source here — DeepSeek Harness
has a native `@deepseek-ai/dsh-mcp-client` package — the same
`mcp.json` used by `integrations/claude-code-plugin/` applies unchanged,
since MCP is not a Claude-Code-specific protocol.
