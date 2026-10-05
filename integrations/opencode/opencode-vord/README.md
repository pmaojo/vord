# opencode-vord

vord's write guardrail as a native [opencode](https://github.com/sst/opencode)
plugin. It does for opencode what [dsh-vord](../../deepseek-harness/dsh-vord)
does for DeepSeek Harness: every judgement runs through the same
`vord hook claude-code` a Claude Code session uses, so `vord-policy.toml`,
protected paths, Gherkin and test evidence, single-use approvals, the circuit
breaker and `.vord-audit.jsonl` all behave identically.

## What it does

| opencode hook | vord behaviour |
|---|---|
| `tool.execute.before` | A `write`, `edit` or `apply_patch` call that would introduce a policy violation throws before the bytes reach disk; the model reads the rule and the line as the tool error. `apply_patch` (what GPT models use instead of `edit`) is judged per added file and per hunk. A recursive `rm` through `bash`, or an `apply_patch` `Delete File`, of code recorded in `.vord/generated.json` is refused the same way. |
| `tool.execute.after` | What landed is re-judged from disk. A violation replaces the tool output with corrective feedback; an advisory is appended to it. A `bash` result (its `metadata.exit`) feeds vord's `[[test_required]]` evidence ledger. |
| `chat.message` | Before a session's first request, records the analyzer's baseline (`vord agent baseline`) once, under `.vord/sessions/<session id>.baseline.json`. Subagent sessions are judged as part of their root session. |
| `event: session.idle` | The definition of done. When a session goes idle while `vord agent done` sees findings the baseline lacked (or `doneRule` still fires), `[[test_required]]` evidence is pending, or a `vord:hole` in a file the session wrote is still empty, vord's objection is sent back into the session as the next message. After `maxStopContinuations` in a row it yields, and the findings still fail CI's gate. |
| `experimental.chat.system.transform` | Standing guidance in the system prompt: scaffold with `vord_vord_kickoff` instead of hand-writing boilerplate, pick the engine by backend language (`ferrum` = Rust, `kthulu` = Go, `wasp` = TypeScript full-stack, `copier` = any template, `openapi` = from a spec), never delete or hand-rewrite generated output. |
| `config` | Mounts `vord mcp` as the `vord` MCP server, so the model calls scan, holes, done, kickoff and the rest as `vord_vord_*` tools. A `vord` server you configure yourself wins. |

### Differences from dsh-vord

- **The done gate is a follow-up message, not a veto.** opencode has no hook
  that can stop a turn from closing, so vord waits for `session.idle` and sends
  its objection as a new user message (`client.session.promptAsync`). The
  model sees it exactly as dsh's `agent.steer` would deliver it, but the turn
  did close first, and the message shows in the transcript.
- **`opencode run` does not wait for it.** The headless `run` command exits as
  soon as the session goes idle, so the done gate cannot send anything back
  there. The write gate, re-judgement, guidance and MCP tools all work in
  `run`; the done gate needs the TUI, `opencode serve` or the web UI. In CI,
  `vord agent done` remains the gate.
- MCP tools are named `<server>_<tool>` by opencode, so vord's `vord_kickoff`
  is `vord_vord_kickoff` (dsh: `mcp__vord__vord_kickoff`).

## Install

`vord` must be on `PATH`, and the workspace needs a `vord-policy.toml`
(`vord hook install` writes a starter one). Add the plugin to the project's
`opencode.json`, with options as the second element:

```json
{
  "$schema": "https://opencode.ai/config.json",
  "plugin": [["/path/to/vord/integrations/opencode/opencode-vord", { "failClosed": false }]]
}
```

A bare `"plugin": ["/path/to/…/opencode-vord"]` takes every default. Add
`.vord/sessions/` to the workspace's `.gitignore`: it holds one baseline per
session.

| Option | Default | Meaning |
|---|---|---|
| `command` | `vord` | vord executable |
| `timeoutMs` | `60000` | per-judgement timeout |
| `failClosed` | `false` | refuse a write when vord itself fails, instead of failing open as vord's own hook does |
| `maxStopContinuations` | `3` | consecutive objections before the done gate yields |
| `analyzerAsDone` | `true` | send the session back on findings it introduced |
| `doneScope` | `.` | path the baseline is taken over and re-scanned |
| `doneRule` | — | a rule every task must eliminate from the scope |
| `holesAsDone` | `touched` | send the session back on pending holes in files it wrote (`touched`), anywhere in scope (`all`), or never (`false`) |
| `guidance` | `true` | standing guidance: `true` the built-in text, a string replaces it, `false` none |
| `mcp` | `true` | mount `vord mcp`: `true` as server `vord`, a string names the server, `false` does not mount it |

The [vord-guardrail skill](../../claude-code-plugin/skills/vord-guardrail) works
in opencode unchanged: opencode loads `.claude/skills/*/SKILL.md`.

opencode-vord has no runtime dependencies.

## Tests

```sh
npm test                                         # unit tests, fake vord
VORD_BIN=../../../target/debug/vord npm test     # also against the real vord binary
```

`test/e2e-opencode.mjs` runs a real opencode with this plugin, a scripted
OpenAI-compatible model and the real vord. It checks that a shell-injection
sink written with `write` is refused and never reaches disk, that the guidance
and the `vord_vord_*` tools reach the model, and (through `opencode serve`)
that the same sink written through `bash` gets vord's objection sent back into
the session. It installs opencode and a provider package, so it is not part of
`npm test`; the steps are at the top of the file.

Verified against `opencode-ai@1.18.34`. Some hooks used here are marked
experimental by opencode, so re-run the e2e after an upgrade.
