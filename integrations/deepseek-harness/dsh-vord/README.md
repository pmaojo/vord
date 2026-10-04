# dsh-vord

vord's write guardrail as a native [DeepSeek Harness](https://github.com/deepseek-ai/deepseek-harness)
plugin, plus a profile bundle that also mounts `vord mcp` as tools. This is the
first piece of "Vord Harness": vord shipped as a distribution of dsh plugins
rather than a fork of dsh.

## What it does

| dsh extension point | vord behaviour |
|---|---|
| `tools/pre-execute` | A `write`, `edit` or `str_replace_editor` call that would introduce a policy violation is denied before the bytes reach disk. The denial names the rule and the line. |
| `tools/post-execute` | What landed is re-judged from disk. A violation blocks the result with corrective feedback, and an advisory is attached as context for the next request. A `bash` result feeds vord's `[[test_required]]` evidence ledger. |
| `agent/created` (guidance) | A new session (not a resume) is given standing guidance as a user-role message: scaffold with the `vord_kickoff` MCP tool instead of hand-writing boilerplate, run `plan` first, pick the engine by backend language (`ferrum` = Rust, `kthulu` = Go, `wasp` = TypeScript full-stack, `copier` = any template such as Python/FastAPI, `openapi` = from a spec), never delete or hand-rewrite generated output (change the blueprint and regenerate; fill holes via `vord_holes`), and open the generated project as the workspace. See `guidance` below. |
| `agent/created` | Records the analyzer's baseline for the session (`vord agent baseline`), once, under `.vord/sessions/`. A resumed session keeps the baseline it started with. |
| `agent/turn-stopping` | The analyzer is the definition of done. A turn cannot close while `vord agent done` sees findings the baseline lacked (or `doneRule` still fires), nor while `[[test_required]]` evidence is pending. The objection steers the agent into another step, so a sink smuggled in through `bash` is still caught. After `maxStopContinuations` forced continuations in a row it yields, and the findings still fail CI's gate. No model's opinion of its own work is consulted. |
| `agent/turn-stopping` (holes) | A turn cannot close while a `vord:hole` in a file the session wrote is still empty or a placeholder, as `vord holes` sees it. With `holesAsDone: all`, any pending hole in `doneScope` holds it open: a profile whose job is filling holes. |
| `mcp-vord` row | `vord mcp` is mounted through `dsh-mcp-client`, so the model calls scan, holes, done, kickoff (templates or a scaffolding engine) and the swarm handoff as `mcp__vord__*` tools. Each one runs the real `vord` command and reports a failure as an error. |

Every judgement runs through the same `vord hook claude-code` a Claude Code
session uses, so `vord-policy.toml`, protected paths, Gherkin and test evidence,
single-use approvals, the circuit breaker and `.vord-audit.jsonl` all behave
identically. The only work this package does is translating dsh's tool calls
into that payload. dsh's `write`/`edit` already take Claude Code's argument
names, and `str_replace_editor` is mapped command by command (`insert` is
judged on the finished file).

Unlike the [Claude Code hook bridge](../README.md), tool names are matched
natively, so the bridge's case-sensitive `Edit|Write` matcher gotcha does not
apply.

## Install

`vord` must be on `PATH`, and the session workspace needs a
`vord-policy.toml` (`vord hook install` writes a starter one).

```sh
dsh vord --from-default-profile headless --dump-config > /dev/null   # or web, sdk…
dsh plugin --profile vord add "file:/path/to/vord/integrations/deepseek-harness/dsh-vord"
dsh vord "remove the shell injection in scripts/deploy.py"
```

Override any row from your profile's `cordis.patch.yml` by id (`vord`,
`mcp-vord`):

| Config | Default | Meaning |
|---|---|---|
| `command` | `vord` | vord executable |
| `timeoutMs` | `60000` | per-judgement timeout |
| `failClosed` | `false` | deny a write when vord itself fails, instead of failing open as vord's own hook does |
| `maxStopContinuations` | `3` | consecutive forced continuations before the Stop gate yields |
| `analyzerAsDone` | `true` | hold the turn open on findings the session introduced |
| `doneScope` | `.` | path the baseline is taken over and re-scanned |
| `doneRule` | — | a rule every task in this profile must eliminate from the scope |
| `guidance` | `true` | standing guidance sent when a new session starts: `true` sends the built-in text (`DEFAULT_GUIDANCE`), a string replaces it, `false` sends nothing |
| `holesAsDone` | `touched` | hold the turn open on pending holes in files the session wrote (`touched`), anywhere in scope (`all`), or never (`false`) |

Add `.vord/sessions/` to the workspace's `.gitignore`: it holds one baseline
file per session.

dsh-vord has no runtime dependencies, so `dsh plugin add` works without
resolving dsh's own packages. `file:` installs are a snapshot: re-run
`dsh plugin add` after changing the plugin.

## Tests

```sh
npm ci
npm test                                         # unit tests, fake vord
VORD_BIN=../../../target/debug/vord npm test     # also against the real vord binary
```

`test/e2e-dsh.mjs` boots the published dsh headless app with this bundle, a
scripted model and the real vord. It checks three things (the third: the standing guidance is in the request the model receives): a shell-injection sink
written with `write` is denied and never reaches disk, and the same sink
written through `bash` keeps the turn open with the analyzer's objection. It installs dsh, so
it is not part of `npm test`; the steps are at the top of the file.

### Trying it on dsh's web harness

These steps were not run here (only the headless e2e above was); treat them as
unverified.

```sh
export DSH_HOME=$(mktemp -d)                      # isolated profiles
dsh vord --from-default-profile web --dump-config > /dev/null
dsh plugin --profile vord add "file:/path/to/vord/integrations/deepseek-harness/dsh-vord"
dsh vord --no-open --port 0                       # prints the local URL
```

Verified against `@deepseek-ai/dsh@0.2.0-rc.2`. dsh is pre-stable, so re-run
the e2e after a dsh upgrade.
