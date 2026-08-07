---
name: vord-static-analysis
description: "Ultra-fast (<30ms) multi-language static analysis, agent write-gating, and spec-driven swarm coordination powered by the vord CLI and vord MCP server."
---

# vord Static Analysis & Guardrail

`vord` is a Rust static analysis engine with a `vord mcp` stdio server
(`mcpServers.vord` in this plugin's `mcp.json`) exposing scan/fix tools
directly to any MCP client, plus a CLI for scanning, fixing, and
coordinating multi-agent swarms.

## Prerequisite

The `vord` binary must be on `PATH`:

```sh
curl -fsSL https://raw.githubusercontent.com/pmaojo/vord/main/scripts/install.sh | sh
vord --version
```

## Capabilities

1. **Scan a workspace** (via CLI or the `vord_scan` MCP tool):
   ```sh
   vord scan .
   ```
2. **Apply automated fixes**:
   ```sh
   vord scan --fix
   vord fix --path <file_path> --issue <rule_id>
   ```
3. **Enforce a quality gate** (e.g. in CI, or before an agent's write lands):
   ```sh
   vord scan . --enforce-gate
   ```
4. **Coordinate a multi-agent swarm** with policy-scoped worktrees and
   durable handoffs — see `vord swarm roles`, `vord swarm run`, and the
   full walkthrough in this repository's root `SKILL.md`.

## Guidance

- Re-run `vord scan .` after any code modification; target 0
  blocker/critical issues before handing work off.
- Full command reference, the swarm architecture, and the Issue Triage
  Factory workflow live in the repository root `SKILL.md` — read that for
  anything beyond the quick capabilities above.
