# yunq AI Agent & Swarm Skill Instructions

`yunq` is an ultra-fast, multi-language static analysis engine and spec-driven agent swarm coordinator written in Rust.

---

## 🏆 The Perfect AI Agent Flow with `yunq`

```
  1. Kickoff / Init ──► 2. Worktree Isolation ──► 3. Fast AST Edit-Scan Loop ──► 4. Policy Gate Verification ──► 5. Handoff & Merge
   (yunq kickoff)          (yunq swarm)             (yunq scan <30ms)               (blocking_rules = 0)         (git merge)
```

### Phase 1: Onboarding & Repository Kickoff
1. **Initialize Project / Feature**:
   - Run `yunq kickoff react-bulletproof` (or `rust-clean`, `python-clean`, `typescript-clean`) to generate a clean, modular structure.
   - Or run `yunq init` to generate a project-tailored `yunq.toml`.

---

### Phase 2: Topology Resolution & Worktree Isolation
2. **Query Swarm Topology**:
   - Run `yunq swarm roles` to resolve active roles (`architect` -> `coder` -> `cleaner` -> `qa`), worktree paths (`.yunq/worktrees/<role>`), protected paths, and blocking rules.

---

### Phase 3: Autonomous Edit-Scan-Fix Loop (< 30ms)
3. **Execute Code Changes inside Worktree**:
   - Edit files inside `.yunq/worktrees/<role>`.
4. **Instant AST Verification**:
   - Run `yunq scan` inside the worktree.
   - `yunq` runs Oxlint (JS/TS), Ruff (Python), Clippy (Rust), and custom React Doctor/OWASP/AI guardrails in < 30ms.
5. **Self-Correction & Automated Fixes**:
   - Run `yunq scan --fix` to apply automated fixes.
   - If manual fixes are needed, inspect `yunq`'s `file:line:col` findings and fix immediately.

---

### Phase 4: Policy Gate Verification & Durable Handoff
6. **Verify Policy Scope**:
   - Ensure zero modifications to `protected_paths` and zero `blocking_rules` errors.
7. **Send Handoff to Next Role**:
   ```bash
   yunq swarm handoff-send --from architect --to coder --summary "Architectural boundaries established"
   yunq swarm handoff-deliver
   ```

---

### Phase 5: Pipeline Completion & Git Merge
8. **Final QA Verification**:
   - Run `yunq scan` across the workspace. Verify health score (e.g., 98/100).
9. **Merge Worktree Branch to Main**:
   - Merge `yunq/swarm/<role>` into `main` and clean up temporary worktrees:
     ```bash
     git merge yunq/swarm/coder
     yunq swarm worktree-remove --role coder
     ```

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

## 🤖 How an AI Agent Drives `yunq swarm` Flows When LLM Provider is Not Configured

When `yunq agent` (the internal LLM runner inside `yunq`) is not configured with an API key or local model provider, **you (the interactive AI Coding Assistant) step in as the model runner for each role in the swarm topology**.

### Step-by-Step AI Agent Execution Protocol:

1. **Query Topology & Role Contracts**:
   - Run `yunq swarm roles` to resolve active roles (`architect` -> `coder` -> `cleaner` -> `qa`), worktree paths, protected paths, and blocking rules.

2. **Trigger Pipeline Run**:
   - Run `yunq swarm run --task "<user_task>"`.
   - `yunq swarm` will attempt to launch the first role. Upon encountering no LLM provider, it emits the **`SWARM ASSISTANT HANDOFF PROMPT`**:
     ```text
     yunq swarm: LLM provider unavailable for role [architect]
     >>> SWARM ASSISTANT HANDOFF PROMPT (role: architect) <<<
     Worktree: /path/to/project/.yunq/worktrees/architect
     Task: <task_description>
     Policy Scope: blocking_rules=["react:feature-directory-isolation"], protected_paths=["infra/"]
     >>> END PROMPT <<<
     ```

3. **Execute Role Task inside Target Worktree**:
   - Navigate your file edits to the target worktree path (`.yunq/worktrees/<role>`).
   - **Obey Scoped Policy**:
     - Do NOT edit files under `protected_paths`.
     - Run `yunq scan` inside the worktree and fix all violations matching `blocking_rules`.

4. **Send & Deliver Handoff to Next Role**:
   - Once the role's work is complete, queue a handoff for the next role in the topology:
     ```bash
     yunq swarm handoff-send --from architect --to coder --summary "Architectural boundaries established and verified"
     yunq swarm handoff-deliver
     ```

5. **Drive Recipient Role Inbox**:
   - Read the incoming handoff for the recipient role:
     ```bash
     yunq swarm handoff-inbox --role coder
     ```
   - Perform the next role's task in its worktree (`.yunq/worktrees/coder`).
   - Acknowledge receipt once complete:
     ```bash
     yunq swarm handoff-ack --role coder --id <handoff_id>
     ```

6. **Monitor & Inspect via TUI**:
   - Launch `yunq swarm tui` at any time to inspect active worktree branches, pending handoffs, and policy scope metrics in a terminal interface.

---

## 🐝 `yunq swarm` Architecture Reference

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
