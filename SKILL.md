# yunq AI Agent & Swarm Skill Instructions

`yunq` is an ultra-fast, multi-language static analysis engine and spec-driven agent swarm coordinator written in Rust.

---

## ⚡ CLI Quick Reference

```bash
# 🚀 1. Kickoff Starter Templates
yunq kickoff react-bulletproof --path ./my-app
yunq kickoff rust-clean --path ./my-rust-crate
yunq kickoff python-clean --path ./my-python-app
yunq kickoff typescript-clean --path ./my-ts-app

# 🔍 2. Static Analysis & Rules
yunq scan                         # Scan workspace using yunq.toml profile
yunq scan --fix                   # Apply automated rule fixes

# 🐝 3. Swarm & Multi-Worktree Orchestration (LLM or Offline Spec-Driven)
yunq swarm roles                  # View resolved role topologies and policy scopes
yunq swarm tui                    # Interactive Ratatui dashboard for roles & handoffs
yunq swarm worktree-create --role coder  # Create isolated git worktree for role
yunq swarm handoff-send --from architect --to coder --summary "Task..."
yunq swarm handoff-deliver        # Deliver queued outbox handoffs into inboxes
yunq swarm handoff-inbox --role coder    # Read role inbox
yunq swarm handoff-ack --role coder --id <id> # Acknowledge handoff
yunq swarm run --task "Ship feature"     # Drive full pipeline (with Assistant prompt fallbacks)
```

---

## 🐝 How `yunq swarm` Works Without an LLM Configured

`yunq swarm` is designed to function **100% offline and spec-driven** without requiring active LLM API keys or local LLM servers.

```
       ┌────────────────┐
       │   yunq.toml    │ (Defines topology & role policies)
       └───────┬────────┘
               │
   ┌───────────▼───────────┐
   │  yunq swarm topology  │ (architect -> coder -> cleaner -> qa)
   └───────────┬───────────┘
               │
 ┌─────────────┼─────────────┬─────────────┐
 │ Worktree 1  │ Worktree 2  │ Worktree 3  │ ... (.yunq/worktrees/<role>)
 │  architect  │    coder    │   cleaner   │
 └──────┬──────┴──────┬──────┴──────┬──────┘
        │             │             │
        ▼             ▼             ▼
 ┌─────────────────────────────────────────┐
 │       Durable Handoff Inbox/Outbox      │ (.yunq/handoffs/)
 └────────────────────┬────────────────────┘
                      │
                      ▼
 ┌─────────────────────────────────────────┐
 │   Swarm Assistant Prompt Fallback / TUI │ (yunq swarm tui)
 └─────────────────────────────────────────┘
```

### 1. Specification-Driven Topology & Worktrees
- Configured in `yunq.toml`:
  ```toml
  [swarm]
  topology = "four-pack" # architect -> coder -> cleaner -> qa

  [[swarm.role]]
  name = "coder"
  blocking_rules = ["react:feature-directory-isolation"]
  protected_paths = ["infra/", "core/"]
  ```
- Each role executes inside its own isolated git worktree (`.yunq/worktrees/<role>`) on a dedicated branch (`yunq/swarm/<role>`), ensuring zero accidental collateral edits across features.

### 2. Durable Handoff Protocol
- Handoffs are plain JSON files stored under `.yunq/handoffs/`:
  - `outbox/`: Pending outgoing handoffs.
  - `inbox/`: Delivered messages waiting for the recipient role.
  - `sent/`: Acknowledged historical handoffs.
- Roles pass structured progress summaries and constraints down the pipeline without needing an active LLM memory context.

### 3. Swarm Assistant Prompt Fallback
- When `yunq swarm run` is executed without a configured LLM provider, `yunq swarm` automatically outputs a structured **Swarm Assistant Handoff Prompt**:
  ```text
  >>> SWARM ASSISTANT HANDOFF PROMPT (role: architect) <<<
  Worktree: /path/to/project/.yunq/worktrees/architect
  Task: Implement clean architecture layer boundaries
  Policy Scope: blocking_rules=["architecture:folder-naming-casing"], protected_paths=["core/"]
  >>> END PROMPT <<<
  ```
- The active AI pair programmer (or human developer) receives the exact role contract and worktree target to complete the task directly!

### 4. Interactive Ratatui Dashboard (`yunq swarm tui`)
- Launch the interactive terminal UI:
  ```bash
  yunq swarm tui
  ```
- Features real-time topology order, worktree status, protected path metrics, and handoff inbox queues with single-key shortcuts (`[d]` deliver handoffs, `[r]` refresh, `[q]` quit).
