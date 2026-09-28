---
name: vord-guardrail
description: "What vord's write-time guardrail blocks, why, and how to fix a denied Edit/Write, for agents working in a repository where this plugin is installed."
---

# vord Guardrail

This plugin wires vord's Agent Permission Policy into `PreToolUse`/
`PostToolUse` hooks on `Edit|Write`. Claude Code loads that wiring from
`.claude-plugin/plugin.json` + `hooks/hooks.json`, referenced for other
spec-aware tooling under `extensions.com.anthropic.claude-code` in this
plugin's root `plugin.json`. The same policy is also queryable directly
via this plugin's `vord` MCP server (`mcp.json`).

## What gets denied

A write is denied when it introduces a finding at or above the active
policy's `block_at_or_above`, or matches `blocking_rules` outright — see
the repository's own `vord-policy.toml` (written by `vord hook install`,
or vord's built-in default if none exists).

## What it does not do

- Does not run a scan of its own accord, install a policy file, or touch
  `.claude/settings.json` — only the hook wiring is added. Run
  `vord hook install` once per repository for a reviewable
  `vord-policy.toml`.
- Fails open: a missing `vord` binary, an unreadable policy, or a
  malformed payload lets the write proceed and reports on stderr.

## Fixing a denied write

Run `vord scan <file>` on the file that was denied, read the
`file:line:col` finding it reports, and either fix it directly or run
`vord scan --fix` for an automated fix where one exists.
