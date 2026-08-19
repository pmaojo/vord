//! Agentic guardrail: vord inside an autonomous agent's edit loop.
//!
//! Every other entry point in this binary answers "what is wrong with this
//! code?" after the fact. This one answers "may this write happen?" *before*
//! the bytes hit disk, in the window between an agent deciding to edit a file
//! and the edit landing — which is the only moment where a finding costs the
//! agent one retry instead of costing a reviewer a pull request.
//!
//! # Why a hook rather than a tool the agent may call
//!
//! An MCP tool or an LSP is *consulted*: the agent decides whether to ask,
//! and an agent optimising for task completion learns not to ask. A host
//! hook is *invoked* — the runtime runs it on every matching tool call, and
//! the agent cannot route around it. That difference is the entire point:
//! this is a guardrail, not a linter the model may consult.
//!
//! # Host contracts
//!
//! The two hook points are not symmetric, and the asymmetry drives the
//! design:
//!
//! - **`PreToolUse`** fires before the tool runs and *can deny it*
//!   (`permissionDecision: "deny"`). The file does not exist yet, so the
//!   content analysed is the content the agent proposed — reconstructed from
//!   the tool's own arguments (see [`proposed_content`]). This is where
//!   prevention happens.
//! - **`PostToolUse`** fires after the write has already landed and cannot
//!   un-write it. It can only feed text back into the model's context. This
//!   is where explanation happens.
//!
//! So: `PreToolUse` prevents, `PostToolUse` teaches. A denial in `PreToolUse`
//! is a real block; the same finding surfaced in `PostToolUse` is a
//! "you just introduced this, fix it" note.
//!
//! Codex CLI ships a hook system modelled on the same payload shape, but its
//! tool hooks fire for shell commands only — not for file writes — so an
//! edit-time guardrail cannot be installed there today. [`run_check`] is the
//! portable path for those hosts (and for `pre-commit`, and for CI): a plain
//! "analyse this file, exit non-zero if policy denies" command with no host
//! contract at all.
//!
//! # Failing open
//!
//! Every unexpected error here — malformed payload, unreadable file, a policy
//! file that does not parse — lets the write proceed and reports on stderr.
//! A guardrail that bricks the agent loop on its own bug is removed within a
//! day, and a removed guardrail blocks nothing at all. Denials are only ever
//! issued from a policy that parsed and an analysis that ran. The one place
//! this is deliberately reversed is [`run_check`], whose non-interactive
//! callers (CI, `pre-commit`) can tell exit 1 (vord broke) from exit 2
//! (policy denied) and decide for themselves.

use std::collections::{HashMap, HashSet};
use std::hash::{Hash, Hasher};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use vord_agent_policy::{
    AgentPolicy, Cause, CircuitBreakerState, Enforcement, Evaluation, Finding, Provenance,
    Violation,
};
use vord_infra_memory::{InMemoryIssueStorage, InMemoryMetricsTracker};
use vord_rules_engine::RuleId;

/// Filename of the Agent Permission Policy, read from the repository root.
pub const POLICY_FILE: &str = "vord-policy.toml";

/// Filename of the circuit breaker's persisted per-rule failure counts, read from and written to
/// the repository root alongside the policy.
pub const CIRCUIT_BREAKER_FILE: &str = ".vord-circuit-breaker.json";

/// Filename of the escalation approval store: tokens a human has authorized via `vord hook
/// approve`, each consumed the next time the matching write is judged.
pub const APPROVALS_FILE: &str = ".vord-approvals.json";

/// Filename of the loop alarm's persisted "last write" signature and streak count.
pub const LOOP_GUARD_FILE: &str = ".vord-loop-guard.json";

/// Filename of the append-only audit log of every non-silent verdict this guardrail has issued.
pub const AUDIT_LOG_FILE: &str = ".vord-audit.jsonl";

/// Filename of the per-path AI-touch ledger: every path a `vord hook` write
/// has ever targeted, denied or not — an attempted edit is itself a signal
/// worth remembering, since the point is "has an agent been steering this
/// file", not "did every attempt succeed". Read back on the next judgement to
/// decide whether [`Provenance::AiTouched`]'s stricter policy applies. This
/// is the automatic, per-file analogue of the "flag this project as
/// AI-generated" setting incumbent AI-code-assurance tools require a human
/// to set by hand.
pub const PROVENANCE_FILE: &str = ".vord-provenance.json";

/// Loads the AI-touch ledger, or an empty one when the file is missing or
/// unreadable. Same fail-open posture as [`load_circuit_breaker`]: a lost
/// ledger only means a path is (re-)judged as untouched, never a bypassed
/// policy — `[agent.ai_touched]` only ever tightens, so forgetting a touch
/// makes the *next* write on that path more permissive, not less safe.
pub fn load_provenance(root: &Path) -> HashSet<String> {
    let path = root.join(PROVENANCE_FILE);
    let Ok(raw) = std::fs::read_to_string(&path) else {
        return HashSet::new();
    };
    serde_json::from_str::<Vec<String>>(&raw)
        .map(|paths| paths.into_iter().collect())
        .unwrap_or_default()
}
