# vord Guardrail (Claude Code plugin)

Wires vord's Agent Permission Policy into every Claude Code session as a
`PreToolUse`/`PostToolUse` hook on `Edit|Write` — the same wiring
`vord hook install` writes into a repository's own `.claude/settings.json`,
packaged as an installable plugin instead of a one-time codegen step.

## Prerequisite

The `vord` binary must be on `PATH`. This plugin does not build or vendor
it — vord is a Rust workspace, not something a Claude Code plugin can bundle
as a script. From a checkout of [pmaojo/vord](https://github.com/pmaojo/vord):

```sh
cargo install --path bin/cli
vord --version   # confirms it resolved
```

(A prebuilt release binary from the repo's Releases page works too, once
placed on `PATH` as `vord`.)

## What it does, and does not do

- Denies a write when it introduces a finding at or above the active
  policy's `block_at_or_above`, or matches `blocking_rules` outright — see
  the repository's own `vord-policy.toml` (written by `vord hook install`,
  or the built-in default if none exists) for what that means in practice.
- Does **not** run a scan of its own accord, install a policy file, or touch
  `.claude/settings.json` — it only adds the hook wiring. Run
  `vord hook install` once per repository to get a reviewable
  `vord-policy.toml` alongside it.
- Fails open: a missing `vord` binary, an unreadable policy, or a malformed
  payload lets the write proceed and reports on stderr, the same posture
  `vord hook` always takes (see the repository root README's "Failing
  open" section).

## Local install (this repo as its own marketplace)

```
/plugin marketplace add pmaojo/vord
/plugin install vord-guardrail@vord
```

## Agent Plugins Specification compliance

Alongside Claude Code's own `.claude-plugin/plugin.json` + `hooks/hooks.json`
(unchanged, and still what Claude Code actually loads), this directory is
also a plugin under the
[Agent Plugins Specification](https://github.com/agentplugins/agent-plugins-spec)
v1.0.0:

- `plugin.json` — the spec's root manifest, `extensions.com.anthropic.claude-code`
  pointing at Claude Code's own manifest for spec-aware tooling.
- `skills/vord-guardrail/SKILL.md` — the same guardrail behavior described
  as a discoverable Agent Skill.
- `mcp.json` — vord's own MCP server (`vord mcp`, stdio transport) as the
  `vord` server, so a spec-conformant client that only supports MCP
  servers (not Claude Code hooks) can still query vord.

`.claude-plugin/` and `hooks/` stay where Claude Code requires them; the
spec's own required root location for `plugin.json` is a separate file,
not a replacement.
