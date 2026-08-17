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

/// Persists the AI-touch ledger. Best-effort: a write failure is reported on
/// stderr rather than surfaced as a denial, matching every other piece of
/// soft state this module keeps (circuit breaker, loop guard).
pub fn save_provenance(root: &Path, touched: &HashSet<String>) {
    let mut entries: Vec<&String> = touched.iter().collect();
    entries.sort();
    let path = root.join(PROVENANCE_FILE);
    match serde_json::to_string_pretty(&entries) {
        Ok(raw) => {
            if let Err(e) = std::fs::write(&path, raw) {
                eprintln!(
                    "vord hook: could not persist provenance ledger at {}: {e}",
                    path.display()
                );
            }
        }
        Err(e) => eprintln!("vord hook: could not serialize provenance ledger: {e}"),
    }
}

/// The provenance a path carries given the ledger seen so far.
pub fn provenance_for(touched: &HashSet<String>, path: &str) -> Provenance {
    if touched.contains(path) {
        Provenance::AiTouched
    } else {
        Provenance::Unestablished
    }
}

/// Records that an agent write has now targeted `path`, persisting only when
/// the ledger actually changes (an already-touched path is a no-op, not a
/// redundant write on every single judgement).
pub fn record_provenance_touch(root: &Path, path: &str) {
    let mut touched = load_provenance(root);
    if touched.insert(path.to_string()) {
        save_provenance(root, &touched);
    }
}

/// The subset of a host's hook payload this guardrail needs. Both Claude
/// Code and Codex CLI send snake_case JSON with these field names; unknown
/// fields (and there are many — session ids, transcripts, permission modes)
/// are ignored rather than rejected, so a host adding fields never breaks
/// the hook.
#[derive(Debug, serde::Deserialize)]
pub struct HookPayload {
    #[serde(default)]
    pub hook_event_name: String,
    #[serde(default)]
    pub tool_name: String,
    #[serde(default)]
    pub tool_input: serde_json::Value,
    #[serde(default)]
    pub cwd: Option<String>,
}

/// What the guardrail decided, independent of how any particular host wants
/// it phrased. Rendering happens in the per-host emitters below.
#[derive(Debug)]
pub enum Verdict {
    /// Nothing to say — stay out of the agent's way entirely.
    Silent,
    /// Policy denied the write.
    Deny {
        path: String,
        evaluation: Evaluation,
    },
    /// Findings worth reporting that do not deny.
    Advise {
        path: String,
        evaluation: Evaluation,
    },
}

impl Verdict {
    /// The evaluation behind this verdict, for a caller that wants the
    /// policy's answer rather than the guardrail's phrasing of it — `vord
    /// agent`'s in-process gate, which renders its own agent-facing text.
    /// [`Verdict::Silent`] yields an empty evaluation: nothing to say is the
    /// same answer as no violations.
    pub fn into_evaluation(self) -> Evaluation {
        match self {
            Verdict::Silent => Evaluation::default(),
            Verdict::Deny { evaluation, .. } | Verdict::Advise { evaluation, .. } => evaluation,
        }
    }

    fn from_evaluation(path: String, evaluation: Evaluation) -> Self {
        if evaluation.is_empty() {
            Verdict::Silent
        } else if evaluation.is_denied() {
            Verdict::Deny { path, evaluation }
        } else {
            Verdict::Advise { path, evaluation }
        }
    }
}

/// Loads the repository's policy, or the built-in default when it has none.
///
/// A policy file that exists but does not parse is an error rather than a
/// silent fallback to the default: the difference between "no policy" and
/// "the policy you wrote has a typo" is exactly the difference the user
/// needs to see, and defaulting would hide a security control failing open.
pub fn load_policy(root: &Path) -> anyhow::Result<AgentPolicy> {
    let path = root.join(POLICY_FILE);
    if !path.exists() {
        return Ok(AgentPolicy::default());
    }
    let raw = std::fs::read_to_string(&path)
        .map_err(|e| anyhow::anyhow!("cannot read {}: {e}", path.display()))?;
    AgentPolicy::parse(&raw).map_err(|e| anyhow::anyhow!("invalid {}: {e}", path.display()))
}

/// `hook check`'s output rendering: prose for a human terminal, or the structured JSON form for
/// automated callers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HookOutputFormat {
    Text,
    Json,
}

/// Loads the circuit breaker's persisted state, or an empty one when the file is missing or
/// unreadable. Same fail-open posture as [`load_policy`] elsewhere in this module, except the
/// failure mode is milder: a corrupt or missing state file only means a forgotten streak, never a
/// bypassed policy, so it is not worth refusing the write over.
pub fn load_circuit_breaker(root: &Path) -> CircuitBreakerState {
    let path = root.join(CIRCUIT_BREAKER_FILE);
    let Ok(raw) = std::fs::read_to_string(&path) else {
        return CircuitBreakerState::default();
    };
    let Ok(counts) = serde_json::from_str::<Vec<CircuitBreakerEntry>>(&raw) else {
        return CircuitBreakerState::default();
    };
    CircuitBreakerState::from_counts(counts.into_iter().filter_map(|entry| {
        RuleId::new(&entry.rule)
            .ok()
            .map(|rule| (rule, entry.count))
    }))
}

/// Persists the circuit breaker's state. Best-effort: a write failure is reported on stderr rather
/// than surfaced as a denial — losing this state merely forgets a streak on the next write, an
/// availability concern for a soft feature, not a security one.
pub fn save_circuit_breaker(root: &Path, state: &CircuitBreakerState) {
    let entries: Vec<CircuitBreakerEntry> = state
        .counts()
        .map(|(rule, count)| CircuitBreakerEntry {
            rule: rule.to_string(),
            count,
        })
        .collect();
    let path = root.join(CIRCUIT_BREAKER_FILE);
    match serde_json::to_string_pretty(&entries) {
        Ok(raw) => {
            if let Err(e) = std::fs::write(&path, raw) {
                eprintln!(
                    "vord hook: could not persist circuit breaker state at {}: {e}",
                    path.display()
                );
            }
        }
        Err(e) => eprintln!("vord hook: could not serialize circuit breaker state: {e}"),
    }
}

/// Deletes the circuit breaker's persisted state — the human-intervention step after a trip:
/// review what the agent could not resolve, then clear the streak before letting it continue.
/// Absence is success, not an error: a breaker that never tripped has nothing to reset.
pub fn reset_circuit_breaker(root: &Path) -> std::io::Result<()> {
    let path = root.join(CIRCUIT_BREAKER_FILE);
    match std::fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct CircuitBreakerEntry {
    rule: String,
    count: u32,
}

/// Which rules (if any) the circuit breaker tripped on this write, computed by folding this
/// write's [`Evaluation`] into the persisted state.
#[derive(Clone, Debug, Default)]
pub struct CircuitBreakerReport {
    pub tripped: Vec<RuleId>,
}

impl CircuitBreakerReport {
    pub fn is_tripped(&self) -> bool {
        !self.tripped.is_empty()
    }
}

/// Loads, updates and persists the circuit breaker state for one verdict. A [`Verdict::Silent`]
/// and a [`Verdict::Advise`] both carry no denials, so folding either in clears every rule's
/// streak — the same "consecutive means uninterrupted" rule [`CircuitBreakerState::record`]
/// applies to a single evaluation applies here across the whole write.
pub fn track_circuit_breaker(root: &Path, verdict: &Verdict) -> CircuitBreakerReport {
    let empty = Evaluation::default();
    let evaluation = match verdict {
        Verdict::Silent => &empty,
        Verdict::Deny { evaluation, .. } | Verdict::Advise { evaluation, .. } => evaluation,
    };
    let mut state = load_circuit_breaker(root);
    let tripped = state.record(evaluation);
    save_circuit_breaker(root, &state);
    CircuitBreakerReport { tripped }
}

// ---------------------------------------------------------------------------
// Escalation approvals
// ---------------------------------------------------------------------------

/// Deterministic identifier for the escalated part of one write, derived
/// from the path and the escalating findings themselves (rule, line,
/// message) rather than the raw proposed content — every call site that
/// needs it (`judge`, `denial_text`, `structured_report`) has an
/// [`Evaluation`] in hand, but not all of them also have the content, and
/// content that reproduces the identical findings is, for approval
/// purposes, the identical write. `None` when nothing in `evaluation`
/// escalated, so callers can use it directly as "is there anything to
/// approve here at all".
///
/// Not cryptographic — this is a workflow token correlating one human's
/// review with one retry, not a security boundary, so `DefaultHasher` (no
/// extra dependency) is enough.
pub fn escalation_token(path: &str, evaluation: &Evaluation) -> Option<String> {
    let mut parts: Vec<String> = evaluation
        .escalations()
        .filter_map(|v| v.finding.as_ref())
        .map(|f| format!("{}:{}:{}", f.rule, f.line, f.message))
        .collect();
    if parts.is_empty() {
        return None;
    }
    parts.sort();

    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    path.hash(&mut hasher);
    parts.join("|").hash(&mut hasher);
    Some(format!("{:016x}", hasher.finish()))
}

/// Loads the set of approved-and-not-yet-consumed escalation tokens, or an empty set when the
/// store is missing or unreadable — the same fail-open posture as [`load_circuit_breaker`]: a
/// lost approval only means a human has to re-approve, never a bypassed policy.
fn load_approvals(root: &Path) -> HashSet<String> {
    let path = root.join(APPROVALS_FILE);
    let Ok(raw) = std::fs::read_to_string(&path) else {
        return HashSet::new();
    };
    serde_json::from_str(&raw).unwrap_or_default()
}

fn save_approvals(root: &Path, approvals: &HashSet<String>) {
    let path = root.join(APPROVALS_FILE);
    match serde_json::to_string_pretty(approvals) {
        Ok(raw) => {
            if let Err(e) = std::fs::write(&path, raw) {
                eprintln!(
                    "vord hook: could not persist approvals at {}: {e}",
                    path.display()
                );
            }
        }
        Err(e) => eprintln!("vord hook: could not serialize approvals: {e}"),
    }
}

/// `vord hook approve <token>`: the human-intervention step for an escalated write. Records the
/// token so the *next* judgement of the matching write consumes it and lets that one write
/// through — approval is single-use and write-specific, never a standing exemption for the rule.
pub fn approve_escalation(root: &Path, token: &str) -> std::io::Result<()> {
    let mut approvals = load_approvals(root);
    approvals.insert(token.to_string());
    save_approvals(root, &approvals);
    Ok(())
}

// ---------------------------------------------------------------------------
// Loop alarm
// ---------------------------------------------------------------------------

/// Consecutive identical writes (same path, same proposed content) that trip the alarm. Same
/// value as the circuit breaker's threshold and for the same reason: low enough to catch a stuck
/// agent before it burns much of its budget, high enough that retrying a genuine fix once or
/// twice never trips it.
const LOOP_TRIP_THRESHOLD: u32 = 3;

#[derive(Debug, Default, serde::Serialize, serde::Deserialize)]
struct LoopGuardState {
    signature: Option<String>,
    count: u32,
}

/// Whether the loop alarm has tripped for the write just tracked, and how many times in a row it
/// has now seen the identical write — independent of whatever the policy decided about it. A
/// clean write repeated forever is exactly as strong a "the agent is stuck" signal as a denied
/// one repeated forever, which is why this tracks every write, not just denials (contrast
/// [`CircuitBreakerState`], which only ever sees denials).
#[derive(Clone, Copy, Debug, Default)]
pub struct LoopGuardReport {
    pub count: u32,
}

impl LoopGuardReport {
    pub fn is_tripped(&self) -> bool {
        self.count >= LOOP_TRIP_THRESHOLD
    }
}

fn write_signature(path: &str, content: Option<&str>) -> String {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    path.hash(&mut hasher);
    content.unwrap_or_default().hash(&mut hasher);
    format!("{:016x}", hasher.finish())
}

fn load_loop_guard(root: &Path) -> LoopGuardState {
    let path = root.join(LOOP_GUARD_FILE);
    let Ok(raw) = std::fs::read_to_string(&path) else {
        return LoopGuardState::default();
    };
    serde_json::from_str(&raw).unwrap_or_default()
}

fn save_loop_guard(root: &Path, state: &LoopGuardState) {
    let path = root.join(LOOP_GUARD_FILE);
    match serde_json::to_string_pretty(state) {
        Ok(raw) => {
            if let Err(e) = std::fs::write(&path, raw) {
                eprintln!(
                    "vord hook: could not persist loop guard state at {}: {e}",
                    path.display()
                );
            }
        }
        Err(e) => eprintln!("vord hook: could not serialize loop guard state: {e}"),
    }
}

/// Folds one write attempt into the persisted "last write" streak. A signature that differs from
/// the last one resets the streak to 1 rather than merely pausing it — like the circuit breaker,
/// "consecutive" means uninterrupted.
pub fn track_loop_guard(root: &Path, path: &str, content: Option<&str>) -> LoopGuardReport {
    let signature = write_signature(path, content);
    let mut state = load_loop_guard(root);
    state.count = if state.signature.as_deref() == Some(signature.as_str()) {
        state.count + 1
    } else {
        1
    };
    state.signature = Some(signature);
    let report = LoopGuardReport { count: state.count };
    save_loop_guard(root, &state);
    report
}

/// Deletes the loop alarm's persisted state — the human-intervention step after a trip, same
/// shape as [`reset_circuit_breaker`].
pub fn reset_loop_guard(root: &Path) -> std::io::Result<()> {
    let path = root.join(LOOP_GUARD_FILE);
    match std::fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

// ---------------------------------------------------------------------------
// Audit log
// ---------------------------------------------------------------------------

/// Appends one JSON line to `.vord-audit.jsonl`. Best-effort, like every other piece of state
/// this module persists: an audit entry that fails to write is reported on stderr, never turned
/// into a denial — this is a record of decisions, not a decision itself.
fn append_audit_entry(root: &Path, entry: serde_json::Value) {
    let Ok(line) = serde_json::to_string(&entry) else {
        return;
    };
    let path = root.join(AUDIT_LOG_FILE);
    match std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
    {
        Ok(mut file) => {
            if let Err(e) = writeln!(file, "{line}") {
                eprintln!(
                    "vord hook: could not append audit log at {}: {e}",
                    path.display()
                );
            }
        }
        Err(e) => eprintln!(
            "vord hook: could not open audit log at {}: {e}",
            path.display()
        ),
    }
}

/// Records one judged write's outcome. A [`Verdict::Silent`] leaves no trace — the same
/// signal-to-noise judgement [`denial_text`]/[`advisory_text`] already make: a guardrail that
/// logs every clean write turns the one log worth auditing into one nobody reads.
pub fn append_audit_log(
    root: &Path,
    event: &str,
    verdict: &Verdict,
    breaker: &CircuitBreakerReport,
    loop_report: &LoopGuardReport,
) {
    let (path, evaluation, outcome) = match verdict {
        Verdict::Silent => return,
        Verdict::Deny { path, evaluation }
            if evaluation.escalations().count() == evaluation.violations.len() =>
        {
            (path, evaluation, "escalation_pending")
        }
        Verdict::Deny { path, evaluation } => (path, evaluation, "deny"),
        Verdict::Advise { path, evaluation } => (path, evaluation, "advise"),
    };
    append_audit_entry(
        root,
        serde_json::json!({
            "timestamp": chrono::Utc::now().to_rfc3339(),
            "event": event,
            "path": path,
            "outcome": outcome,
            "circuit_breaker_tripped": breaker.is_tripped(),
            "loop_alarm_tripped": loop_report.is_tripped(),
            "violations": evaluation.violations.iter().map(|v| violation_json(v, breaker)).collect::<Vec<_>>(),
        }),
    );
}

/// Records a human's approval being consumed — the one event this module logs outside
/// [`append_audit_log`]'s verdict-shaped entries, since by the time `judge` consumes the token
/// the write it applies to has already turned into a `Silent`/`Advise` verdict with no trace of
/// the escalation left to log otherwise.
fn append_escalation_approved_audit(root: &Path, path: &str, token: &str) {
    append_audit_entry(
        root,
        serde_json::json!({
            "timestamp": chrono::Utc::now().to_rfc3339(),
            "event": "escalation_approved",
            "path": path,
            "outcome": "escalation_approved",
            "token": token,
        }),
    );
}

/// Reads the audit log, oldest first, keeping only the most recent `limit` entries (all of them
/// when `None`). A line that fails to parse is skipped rather than failing the whole read — a
/// human-editable JSONL file gathers stray blank lines and typos, and one bad line should not
/// hide every entry around it.
pub fn read_audit_log(root: &Path, limit: Option<usize>) -> Vec<serde_json::Value> {
    let path = root.join(AUDIT_LOG_FILE);
    let Ok(raw) = std::fs::read_to_string(&path) else {
        return Vec::new();
    };
    let mut entries: Vec<serde_json::Value> = raw
        .lines()
        .filter_map(|line| serde_json::from_str(line).ok())
        .collect();
    if let Some(limit) = limit {
        let start = entries.len().saturating_sub(limit);
        entries = entries.split_off(start);
    }
    entries
}

/// Human-readable rendering of [`read_audit_log`]'s output for `vord hook audit`'s default
/// (non-`--format json`) output.
pub fn render_audit_text(entries: &[serde_json::Value]) -> String {
    if entries.is_empty() {
        return format!("vord: no audit log entries yet ({AUDIT_LOG_FILE} not found or empty).\n");
    }
    let mut out = String::new();
    for entry in entries {
        let get = |key: &str| entry.get(key).and_then(|v| v.as_str()).unwrap_or("?");
        out.push_str(&format!(
            "{}  {:<10}  {:<18}  {}\n",
            get("timestamp"),
            get("event"),
            get("outcome"),
            get("path")
        ));
    }
    out
}

/// The structured, machine-readable counterpart to [`denial_text`] / [`advisory_text`]: every
/// violation as a JSON object naming the exact rule, line and the deterministic condition that
/// must hold for it to clear, rather than prose a caller has to pattern-match. This is the
/// contract `hook check --format json` speaks on stdout, and it is also embedded (as a fenced
/// block) inside the prose the Claude Code hook returns, so an agent that wants exact parsing does
/// not have to choose between the two.
pub fn structured_report(
    path: &str,
    evaluation: &Evaluation,
    breaker: &CircuitBreakerReport,
    loop_report: &LoopGuardReport,
) -> serde_json::Value {
    serde_json::json!({
        "path": path,
        "denied": evaluation.is_denied(),
        "circuit_breaker_tripped": breaker.is_tripped(),
        "loop_alarm_tripped": loop_report.is_tripped(),
        "escalation_token": escalation_token(path, evaluation),
        "violations": evaluation.violations.iter().map(|v| violation_json(v, breaker)).collect::<Vec<_>>(),
    })
}

fn violation_json(violation: &Violation, breaker: &CircuitBreakerReport) -> serde_json::Value {
    let (rule, severity, line, message) = match &violation.finding {
        Some(f) => (
            Some(f.rule.to_string()),
            Some(f.severity.to_string()),
            Some(f.line),
            Some(f.message.clone()),
        ),
        None => (None, None, None, None),
    };
    let (cause, expected_state) = match &violation.cause {
        Cause::ProtectedPath { pattern, reason } => (
            "protected_path",
            format!("path must not match `{pattern}` ({reason})"),
        ),
        Cause::BlockingRule => (
            "blocking_rule",
            match &rule {
                Some(r) => format!("no finding for rule `{r}` in this write"),
                None => "no blocking finding in this write".to_string(),
            },
        ),
        Cause::SeverityThreshold { threshold } => (
            "severity_threshold",
            format!("no finding at or above severity `{threshold}` in this write"),
        ),
        Cause::Escalation => (
            "escalation",
            match &rule {
                Some(r) => format!(
                    "write requires human approval for rule `{r}` — see `vord hook approve <token>`"
                ),
                None => "requires human approval".to_string(),
            },
        ),
        Cause::MissingGherkinEvidence { pattern, reason } => (
            "missing_gherkin_evidence",
            format!(
                "path matches `{pattern}` and needs a `@covers(...)`-tagged scenario ({reason})"
            ),
        ),
    };
    let circuit_breaker_tripped = rule
        .as_deref()
        .is_some_and(|r| breaker.tripped.iter().any(|t| t.as_str() == r));
    serde_json::json!({
        "rule": rule,
        "severity": severity,
        "line": line,
        "message": message,
        "enforcement": match violation.enforcement {
            Enforcement::Deny => "deny",
            Enforcement::Warn => "warn",
            Enforcement::Escalate => "escalate",
        },
        "cause": cause,
        "expected_state": expected_state,
        "circuit_breaker_tripped": circuit_breaker_tripped,
    })
}

/// Reconstructs the file content a tool call is *about to* produce, so
/// `PreToolUse` can judge code that does not exist on disk yet.
///
/// Each host tool describes its write differently and none of them hand over
/// the finished file:
/// - `Write` carries the whole new content, so it is used directly.
/// - `Edit` carries a search/replace pair, so the current file is read and
///   the replacement applied exactly as the host will apply it — honouring
///   `replace_all`, which otherwise silently diverges on repeated strings.
/// - Anything else (notebook edits, patches, MCP tools with their own
///   shapes) returns `None`: the path-based half of the policy still
///   applies, but no content analysis is attempted on a guess.
pub fn proposed_content(
    tool_name: &str,
    tool_input: &serde_json::Value,
    file: &Path,
) -> Option<String> {
    let field = |key: &str| tool_input.get(key).and_then(|v| v.as_str());
    match tool_name {
        "Write" => field("content").map(|s| s.to_string()),
        "Edit" => {
            let old = field("old_string")?;
            let new = field("new_string")?;
            let current = std::fs::read_to_string(file).ok()?;
            let replace_all = tool_input
                .get("replace_all")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            Some(if replace_all {
                current.replace(old, new)
            } else {
                current.replacen(old, new, 1)
            })
        }
        _ => None,
    }
}

/// Runs the full analyzer over one file and maps its issues *and hotspots*
/// into policy findings.
///
/// `relative` must be repository-relative: `SourceFile` rejects absolute
/// paths, and the policy's path globs are written against repository-relative
/// paths too.
///
/// `root`'s rest of the project is loaded alongside `relative`/`content` and
/// fed into the same analysis run — not just `relative` on its own. A
/// `CrossFileRule` (`rust:route-without-test-coverage`, `owasp:cross-file-
/// injection`, every architecture/DDD cross-file rule) judges `relative` by
/// evidence that lives in *other* files, e.g. a route string that only a
/// separate `tests/*.rs` proves is exercised. Handing the engine `relative`
/// alone starves every such rule of that evidence unconditionally: it cannot
/// see a covering test no matter how long it has sat committed on disk, so
/// the hook denies writes a full `vord scan .` — which does load the whole
/// project — passes clean. This is what made the discrepancy look like a
/// stale incremental cache from the outside: nothing here is cached or
/// invalidated at all, the single-file call just never had the other file in
/// scope to begin with. Project files are loaded via `vord_infra_fs::
/// collect_sources`, gitignore-aware the same way a full scan is; a load
/// failure (e.g. `root` doesn't exist, as in tests that pass a fake path)
/// degrades to single-file analysis rather than erroring, matching this
/// function's pre-existing behavior. `relative`'s own on-disk copy, if any,
/// is excluded from that set so `content` (which may be proposed, not-yet-
/// written content) is never shadowed by a stale duplicate.
///
/// A `.vord-cache.json` cache (same file, same format `vord scan .` reads
/// and writes) is attached so unchanged project files reuse their prior
/// single-file `Rule` results instead of being fully re-analyzed on every
/// single Edit/Write hook call — `CrossFileRule`s are never cached (see
/// `AnalyzerService::run_cross_file_rules`) and are always freshly
/// recomputed from the full parsed file set, exactly as a full scan already
/// does, so correctness here costs no more than `vord scan .` already pays.
///
/// Returns an empty vector for a file whose extension maps to no language —
/// there is nothing to parse, which is not an error, and the path half of
/// the policy still gets its say.
///
/// Hotspots are included alongside issues, not just issues: `Rule::check` can
/// mark a finding `FindingKind::Hotspot` ("security-sensitive, needs human
/// review" rather than "definite problem"), and several rules in the default
/// policy's own shipped `blocking_rules` — `owasp:command-execution` among
/// them — are hotspot-only by design. `report.issues()` alone never contains
/// those, so a policy naming a hotspot rule in `blocking_rules` would
/// silently never deny anything for it. A hotspot carries no severity of its
/// own (that is the point of the distinction — nothing has judged it yet),
/// so each one borrows the severity the active profile would assign it as an
/// ordinary issue, via the same quality profile the analyzer ran with;
/// `blocking_rules`/`escalate_rules` match by rule id regardless of
/// severity, so this only matters for `block_at_or_above`.
pub async fn analyze_content(
    root: &Path,
    relative: &str,
    content: &str,
) -> anyhow::Result<Vec<Finding>> {
    let extension = Path::new(relative)
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("");
    let Some(language) = vord_ast::LanguageIdentifier::from_extension(extension) else {
        return Ok(Vec::new());
    };
    let source = vord_ast::SourceFile::new(relative.to_string(), content.to_string(), language)
        .map_err(|e| anyhow::anyhow!("invalid source path {relative:?}: {e}"))?;

    let mut sources = vec![source];
    if let Ok(project_sources) = vord_infra_fs::collect_sources(root) {
        sources.extend(
            project_sources
                .into_iter()
                .filter(|file| file.path() != relative),
        );
    }

    let cache = std::sync::Arc::new(vord_infra_fs::FileAnalysisCache::open(
        root.join(".vord-cache.json"),
    ));
    let service =
        crate::default_service(InMemoryIssueStorage::new(), InMemoryMetricsTracker::new())
            .with_cache(cache.clone());
    let report = service.analyze_files(&sources).await?;
    if let Err(e) = cache.persist() {
        eprintln!("warning: could not persist analysis cache: {e}");
    }
    let profile = vord_rules_engine::default_profile();

    let issue_findings = report
        .issues()
        .iter()
        .filter(|issue| issue.file() == relative)
        .map(|issue| Finding {
            rule: issue.rule().clone(),
            severity: issue.severity(),
            message: issue.message().to_string(),
            line: issue.span().start_line,
        });
    let hotspot_findings = report
        .hotspots()
        .iter()
        .filter(|hotspot| hotspot.file() == relative)
        .map(|hotspot| Finding {
            rule: hotspot.rule().clone(),
            severity: profile
                .severity_of(hotspot.rule())
                .unwrap_or(vord_rules_engine::Severity::Major),
            message: hotspot.message().to_string(),
            line: hotspot.span().start_line,
        });

    Ok(issue_findings.chain(hotspot_findings).collect())
}

/// Names every dependency a manifest file declares, keyed by ecosystem
/// format. Only the two highest-risk, highest-volume ecosystems for
/// typosquatting are covered; extending this to Cargo.toml/go.mod/Gemfile
/// is a matter of adding another `match` arm and parser, not a new concept.
fn manifest_dependency_names(
    file_name: &str,
    raw: &str,
) -> Option<std::collections::HashSet<String>> {
    match file_name {
        "package.json" => {
            let value: serde_json::Value = serde_json::from_str(raw).ok()?;
            let mut names = std::collections::HashSet::new();
            for section in [
                "dependencies",
                "devDependencies",
                "peerDependencies",
                "optionalDependencies",
            ] {
                if let Some(obj) = value.get(section).and_then(|v| v.as_object()) {
                    names.extend(obj.keys().cloned());
                }
            }
            Some(names)
        }
        "requirements.txt" => Some(
            raw.lines()
                .map(str::trim)
                .filter(|line| !line.is_empty() && !line.starts_with('#') && !line.starts_with('-'))
                .filter_map(|line| {
                    let name = line
                        .split(['=', '>', '<', '~', '!', ';', '[', ' '])
                        .next()?
                        .trim();
                    (!name.is_empty()).then(|| name.to_ascii_lowercase())
                })
                .collect(),
        ),
        _ => None,
    }
}

/// Findings for dependencies a proposed write adds to a manifest that did not
/// have them before — an agent introducing `left-pad-plus` is a supply-chain
/// risk (typosquatting, an unreviewed transitive tree) categorically
/// different from the AST vulnerabilities the rest of this module looks for,
/// and no `Rule` in `core/rules-engine` sees it: that trait analyses one
/// file's *current* content, with no concept of "before this write". Silent
/// (rather than flagging every dependency) when the manifest did not
/// previously exist — bootstrapping a new project's dependency set is
/// normal, not drift in an established one. Not in the default policy's
/// `blocking_rules`/`advisory_rules` — see `vord-policy.toml`'s template for
/// how to opt in.
fn new_dependency_findings(
    relative: &str,
    old_content: Option<&str>,
    new_content: &str,
) -> Vec<Finding> {
    let Some(old_content) = old_content else {
        return Vec::new();
    };
    let file_name = Path::new(relative)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("");
    let Some(old_names) = manifest_dependency_names(file_name, old_content) else {
        return Vec::new();
    };
    let Some(new_names) = manifest_dependency_names(file_name, new_content) else {
        return Vec::new();
    };

    let mut added: Vec<&String> = new_names.difference(&old_names).collect();
    added.sort();

    let rule = RuleId::new("supply-chain:new-dependency").expect("valid rule id");
    added
        .into_iter()
        .map(|name| Finding {
            rule: rule.clone(),
            severity: vord_rules_engine::Severity::Major,
            message: format!(
                "agent introduced new dependency `{name}` in {relative} — review provenance and check for \
                 typosquatting before this lands"
            ),
            line: 1,
        })
        .collect()
}

/// Suppression / exclusion directives across ecosystems that let code look
/// gate-clean by hiding it from the gate rather than by actually passing it.
/// Each entry is matched as a plain substring of a source line — the same
/// granularity `new_dependency_findings` above uses for manifest names —
/// since these are conventionally single-line pragmas, not AST nodes.
const SUPPRESSION_MARKERS: &[&str] = &[
    "#[allow(",           // Rust
    "// eslint-disable",  // JS/TS, line form
    "/* eslint-disable",  // JS/TS, block form
    "# noqa",             // Python (ruff/flake8)
    "# type: ignore",     // Python (mypy)
    "# pylint: disable",  // Python
    "//nolint",           // Go (golangci-lint)
    "// nolint",          // Go (golangci-lint, spaced)
    "# pragma: no cover", // Python (coverage.py)
    "// istanbul ignore", // JS/TS (Istanbul/nyc coverage)
];

/// Markers that mark a test skipped/ignored rather than fixed. Grouped
/// separately from [`SUPPRESSION_MARKERS`] because it earns its own rule id —
/// "a test was silenced" is a distinct signal from "a lint was silenced",
/// even though both are gate-gaming's same underlying move.
const TEST_SKIP_MARKERS: &[&str] = &[
    "#[ignore]",
    "@pytest.mark.skip",
    "@unittest.skip",
    ".skip(",
    "xit(",
    "xdescribe(",
];

/// Lines matching one of `markers` that appear in `new_content` but not in
/// `old_content` — the mechanical form of "this suppression was added by this
/// write", the same before/after distinction [`new_dependency_findings`]
/// draws for manifests. A line already present before this write is not a
/// finding; the identical line introduced by it is.
fn new_marker_lines(old_content: &str, new_content: &str, markers: &[&str]) -> Vec<String> {
    let matches = |line: &&str| markers.iter().any(|m| line.contains(m));
    let old_lines: HashSet<&str> = old_content.lines().filter(matches).collect();
    new_content
        .lines()
        .filter(matches)
        .filter(|l| !old_lines.contains(l))
        .map(|l| l.trim().to_string())
        .collect()
}

/// Findings for a suppression or coverage-exclusion directive a proposed
/// write adds that was not there before — a `#[allow(...)]`, an
/// `eslint-disable`, a `# noqa`, a `# pragma: no cover`, and their siblings
/// across ecosystems. An agent optimising for "the gate is green" has two
/// strategies: satisfy the gate, or quietly narrow what it can see. This
/// makes the second one an ordinary, reviewable finding instead of an
/// invisible one — no `Rule` in `core/rules-engine` can see it, since that
/// trait analyses one file's *current* content with no concept of "before
/// this write" (same reasoning as `new_dependency_findings` above). Absent
/// `old_content` (a brand-new file) is treated as empty rather than skipped:
/// unlike a bootstrapping dependency set, every suppression in a file an
/// agent just created was, in fact, added by this write. Not in the default
/// policy's `blocking_rules` — see `vord-policy.toml`'s template for how to
/// opt into `advisory_rules`/`escalate_rules`.
fn suppression_added_findings(
    relative: &str,
    old_content: Option<&str>,
    new_content: &str,
) -> Vec<Finding> {
    let old_content = old_content.unwrap_or("");
    let rule = RuleId::new("ai:suppression-added").expect("valid rule id");
    new_marker_lines(old_content, new_content, SUPPRESSION_MARKERS)
        .into_iter()
        .map(|line| Finding {
            rule: rule.clone(),
            severity: vord_rules_engine::Severity::Major,
            message: format!(
                "agent added a new suppression/exclusion directive in {relative}: `{line}` — a gate that is \
                 silenced is not a gate that is satisfied; fix the underlying finding or justify the suppression in \
                 review"
            ),
            line: 1,
        })
        .collect()
}

/// Findings for a test a proposed write newly marks skipped/ignored rather
/// than fixed — `#[ignore]`, `@pytest.mark.skip`, `.skip(`, and their
/// siblings. Same before/after shape as [`suppression_added_findings`]: a
/// skip that was already there is not a finding, the same annotation added by
/// this write is. Not in the default policy's `blocking_rules` — see
/// `vord-policy.toml`'s template for how to opt in.
fn test_skip_added_findings(
    relative: &str,
    old_content: Option<&str>,
    new_content: &str,
) -> Vec<Finding> {
    let old_content = old_content.unwrap_or("");
    let rule = RuleId::new("ai:test-skipped").expect("valid rule id");
    new_marker_lines(old_content, new_content, TEST_SKIP_MARKERS)
        .into_iter()
        .map(|line| Finding {
            rule: rule.clone(),
            severity: vord_rules_engine::Severity::Major,
            message: format!(
                "agent marked a test skipped/ignored in {relative}: `{line}` — a skipped test proves nothing; the \
                 suite must still be able to catch a revert of the change it was meant to guard"
            ),
            line: 1,
        })
        .collect()
}

/// Findings for a `.feature` file whose `@covers(...)` tags claim more than
/// the scenarios under them actually prove. The `[[gherkin_required]]`
/// evidence gate is the one control in this module an agent can lift *by
/// writing a file*, which makes the cheapest way past it a one-line bypass:
///
/// ```gherkin
/// @covers(core/domain/**)
/// Feature: Domain
/// ```
///
/// No scenario, no steps, no behaviour — and every future write to
/// `core/domain/**` waved through. `vord_infra_fs::scan_covers_claims`
/// already refuses to credit such a claim, so the gate itself holds without
/// this function; what this adds is the *explanation*. Silently crediting
/// nothing would deny the agent's next source write with "no Gherkin scenario
/// covers this path" while a file it just wrote appears, to it, to say
/// otherwise — an agent given a contradiction retries it. Two rules, matching
/// the two ways a claim outruns its evidence:
///
/// - `bdd:unverified-scenario` — the block carrying the tag has no
///   `When`/`Then` pair (or is a `Scenario Outline` with no `Examples:` row).
/// - `bdd:overbroad-covers` — the glob is `**` or a synonym, one scenario
///   claiming an entire repository.
///
/// Diff-aware in the same spirit as [`drop_preexisting_findings`]: a claim
/// that was already in the file, unchanged, is not this write's doing, so
/// editing a scenario in a `.feature` file that has an unrelated stub
/// elsewhere in it is not blocked on cleaning up the stub. Neither rule is in
/// the default policy's `blocking_rules` — see `vord-policy.toml`'s template
/// for how to opt in.
fn bdd_feature_findings(
    relative: &str,
    old_content: Option<&str>,
    new_content: &str,
) -> Vec<Finding> {
    if !relative.ends_with(".feature") {
        return Vec::new();
    }
    let already_claimed: HashSet<String> = old_content
        .map(|old| {
            vord_infra_fs::scan_covers_claims(old)
                .into_iter()
                .filter(|claim| !claim.is_credited())
                .map(|claim| claim.pattern)
                .collect()
        })
        .unwrap_or_default();

    let unverified = RuleId::new("bdd:unverified-scenario").expect("valid rule id");
    let overbroad = RuleId::new("bdd:overbroad-covers").expect("valid rule id");
    vord_infra_fs::scan_covers_claims(new_content)
        .into_iter()
        .filter(|claim| !claim.is_credited())
        .filter(|claim| !already_claimed.contains(&claim.pattern))
        .map(|claim| {
            let (rule, message) = if claim.overbroad {
                (
                    overbroad.clone(),
                    format!(
                        "`@covers({})` in {relative} claims the whole repository — no single scenario exercises \
                         every path, so this claim is not credited as Gherkin evidence; scope the glob to the \
                         paths this scenario actually drives",
                        claim.pattern
                    ),
                )
            } else {
                (
                    unverified.clone(),
                    format!(
                        "`@covers({})` in {relative} is not backed by a scenario: the block carrying it has no \
                         When/Then pair (a Scenario Outline also needs an Examples row), so it is not credited as \
                         Gherkin evidence and will not satisfy `[[gherkin_required]]` — write the steps that \
                         describe the behaviour, not just the tag that claims it",
                        claim.pattern
                    ),
                )
            };
            Finding {
                rule,
                severity: vord_rules_engine::Severity::Major,
                message,
                line: u32::try_from(claim.line).unwrap_or(u32::MAX),
            }
        })
        .collect()
}

/// Whether `relative` already has a covering Gherkin scenario, per
/// `[[gherkin_required]]`'s evidence gate. Skips the `.feature`-file scan
/// entirely (returning `true`, i.e. "assume covered") when the policy has no
/// `[[gherkin_required]]` globs at all — `AgentPolicy::evaluate_with_evidence`
/// only ever reads this value for a path that actually matches one, so on an
/// unconfigured repository the answer is inert and not worth a filesystem
/// walk on every single write. A scan that fails (unreadable `.feature`
/// file, walk error) fails open the same way every other check in this
/// module does: report on stderr and treat the write as covered rather than
/// deny over a tooling problem.
fn has_covering_gherkin_scenario(policy: &AgentPolicy, root: &Path, relative: &str) -> bool {
    if !policy.has_gherkin_requirements() {
        return true;
    }
    match vord_infra_fs::GherkinCoverageIndex::build_from_repo(root) {
        Ok(index) => index.covers(relative),
        Err(e) => {
            eprintln!("vord hook: could not scan .feature files for Gherkin evidence: {e}");
            true
        }
    }
}

/// Rule ids whose finding summarizes the *whole file* as a single score —
/// `smells:maintainability-index`'s Maintainability Index, `smells:ck-oo-
/// metrics`'s WMC/CBO — rather than pinpointing a specific line-level
/// pattern. At most one finding per file per rule, and the message text
/// itself (`13.0/100`, `WMC = 49`) drifts on every single edit even when the
/// file's actual shape barely changed, so these are matched by rule alone —
/// see [`drop_preexisting_findings`].
const WHOLE_FILE_METRIC_RULES: &[&str] = &["smells:maintainability-index", "smells:ck-oo-metrics"];

/// Drops any finding in `findings` that already fired, unchanged, on
/// `old_findings` before this write landed — so a write is only ever denied
/// for a violation it actually introduced, never for one the file already
/// contained. This is the file-level analogue of `core/rules-engine`'s New
/// Code baseline (`Baseline`/`NewCodeAnalysis`): that machinery diffs against
/// a stored analysis snapshot for the quality *gate*; this diffs against the
/// content on disk a write is about to replace, for the agent *hook*, where
/// no persisted baseline exists — the previous write's content already
/// serves as one.
///
/// Two matching strategies, chosen per rule:
///
/// - [`WHOLE_FILE_METRIC_RULES`]: matched by rule alone (message text drifts
///   on every edit, see above), dropped once if the rule fired at all before
///   this write. A rule with no matching prior finding (this write is what
///   pushes the file over the threshold) is left in place — a genuinely new
///   violation this write is responsible for.
/// - Every other rule (e.g. per-function complexity, "do not call eval"):
///   matched by the exact `(rule, message)` pair, as a multiset rather than
///   a set, and deliberately *not* by line. A finding's `line` shifts under
///   an edit elsewhere in the file — an inserted comment pushes every line
///   below it down — so a pure comment addition must not turn an untouched
///   function's pre-existing complexity finding into an apparently "new"
///   one just because it now sits three lines lower. Several of these
///   messages also are not unique per occurrence (e.g. "function has
///   cyclomatic complexity 7 (max 10)" says nothing about *which*
///   function), so matching drops only as many occurrences of an identical
///   `(rule, message)` as already existed; the Nth occurrence beyond that
///   count is a genuinely new violation and stays.
fn drop_preexisting_findings(findings: &mut Vec<Finding>, old_findings: &[Finding]) {
    let whole_file_present: HashSet<&str> = old_findings
        .iter()
        .map(|f| f.rule.as_str())
        .filter(|rule| WHOLE_FILE_METRIC_RULES.contains(rule))
        .collect();

    let mut remaining: HashMap<(String, String), usize> = HashMap::new();
    for f in old_findings {
        if WHOLE_FILE_METRIC_RULES.contains(&f.rule.as_str()) {
            continue;
        }
        *remaining
            .entry((f.rule.as_str().to_string(), f.message.clone()))
            .or_insert(0) += 1;
    }

    findings.retain(|f| {
        if WHOLE_FILE_METRIC_RULES.contains(&f.rule.as_str()) {
            return !whole_file_present.contains(f.rule.as_str());
        }
        let key = (f.rule.as_str().to_string(), f.message.clone());
        match remaining.get_mut(&key) {
            Some(count) if *count > 0 => {
                *count -= 1;
                false
            }
            _ => true,
        }
    });
}

/// Judges one proposed write end to end: policy, path, and (when content is
/// available and parseable) findings.
///
/// A path matching `[[gherkin_required]]` with no covering `@covers(...)`
/// scenario anywhere in the repository's `.feature` files denies with no
/// finding needed, via [`has_covering_gherkin_scenario`] and
/// [`AgentPolicy::evaluate_with_evidence`] — the mechanical version of
/// Uncle Bob's "surround the agent with constraints" gauntlet: no scenario,
/// no landed write. Only a claim `vord_infra_fs::scan_covers_claims` credits
/// counts, so the gate cannot be lifted by writing a tag over an empty
/// feature file; [`bdd_feature_findings`] tells the agent when it has written
/// one.
///
/// Before evaluating, the path's [`Provenance`] is looked up in the AI-touch
/// ledger (`.vord-provenance.json`) and passed to
/// [`AgentPolicy::evaluate_with_provenance`], so a path with prior agent
/// history is judged against `[agent.ai_touched]`'s stricter threshold. The
/// touch is then recorded unconditionally — including on this very write,
/// whether it ends up denied or not — so a repeatedly-retried denied write
/// still escalates the path's provenance for the next attempt, and a path an
/// agent has only ever attempted (never landed) still reads as AI-touched:
/// the point is "has an agent been steering this file", not "did the write
/// succeed".
///
/// The last step consumes a pending escalation approval: when every
/// violation in an otherwise-denied evaluation is an [`Enforcement::Escalate`]
/// (never when a hard `Deny` is mixed in — see [`Cause::BlockingRule`]'s "no
/// exceptions" invariant), a matching token in `.vord-approvals.json` is
/// removed and the write is re-judged against whatever remains. This is the
/// only place approval state is read, keeping it out of the pure
/// `vord-agent-policy` evaluation itself.
pub async fn judge(
    policy: &AgentPolicy,
    root: &Path,
    file: &Path,
    content: Option<&str>,
) -> anyhow::Result<Verdict> {
    let relative = relative_to(root, file);
    let mut findings = match content {
        Some(content) => analyze_content(root, &relative, content).await?,
        None => Vec::new(),
    };
    // Only meaningful `PreToolUse`-side, where disk still holds the
    // pre-write content: by the time a write has landed (`PostToolUse`,
    // `hook check`), disk already matches `content` and the diff is empty.
    if let Some(content) = content {
        let old_content = std::fs::read_to_string(file).ok();
        if let Some(old) = old_content.as_deref() {
            let old_findings = analyze_content(root, &relative, old).await?;
            drop_preexisting_findings(&mut findings, &old_findings);
        }
        findings.extend(new_dependency_findings(
            &relative,
            old_content.as_deref(),
            content,
        ));
        findings.extend(suppression_added_findings(
            &relative,
            old_content.as_deref(),
            content,
        ));
        findings.extend(test_skip_added_findings(
            &relative,
            old_content.as_deref(),
            content,
        ));
        findings.extend(bdd_feature_findings(
            &relative,
            old_content.as_deref(),
            content,
        ));
    }
    let provenance = provenance_for(&load_provenance(root), &relative);
    let has_scenario = has_covering_gherkin_scenario(policy, root, &relative);
    let evaluation = policy.evaluate_with_evidence(&relative, &findings, provenance, has_scenario);
    record_provenance_touch(root, &relative);
    let verdict = Verdict::from_evaluation(relative, evaluation);

    let Verdict::Deny { path, evaluation } = &verdict else {
        return Ok(verdict);
    };
    let no_hard_deny = !evaluation
        .violations
        .iter()
        .any(|v| v.enforcement == Enforcement::Deny);
    if !no_hard_deny {
        return Ok(verdict);
    }
    let Some(token) = escalation_token(path, evaluation) else {
        return Ok(verdict);
    };
    let mut approvals = load_approvals(root);
    if !approvals.remove(&token) {
        return Ok(verdict);
    }
    save_approvals(root, &approvals);
    append_escalation_approved_audit(root, path, &token);

    let residual: Vec<Violation> = evaluation
        .violations
        .iter()
        .filter(|v| v.enforcement != Enforcement::Escalate)
        .cloned()
        .collect();
    Ok(Verdict::from_evaluation(
        path.clone(),
        Evaluation {
            violations: residual,
        },
    ))
}

/// Re-bases an absolute tool path onto the repository root the policy globs
/// are written against. A path outside the root (or one already relative)
/// is returned normalised, so it still matches `**`-anchored globs rather
/// than silently escaping the policy.
pub fn relative_to(root: &Path, file: &Path) -> String {
    let normalise = |p: &Path| p.to_string_lossy().replace('\\', "/");
    match file.strip_prefix(root) {
        Ok(relative) => normalise(relative),
        Err(_) => normalise(file.strip_prefix("/").unwrap_or(file)),
    }
}

/// Whether the write being judged has already landed on disk. The agent
/// needs this to be exact: told "blocked" about a file that was in fact
/// written, a model reasonably concludes the edit did not happen and moves
/// on leaving the vulnerability in the tree.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Timing {
    /// `PreToolUse` — the write was prevented, nothing changed on disk.
    Prevented,
    /// `PostToolUse` — the write already happened and must be undone or fixed.
    AlreadyWritten,
}

/// The agent-facing explanation of a denial. Written to be *acted on* by a
/// model, not filed by a human: it names the file, enumerates the exact
/// violations with rule id and line, and states plainly that this is a
/// policy block rather than a suggestion — an agent given a soft-sounding
/// refusal will retry the identical write.
pub fn denial_text(
    path: &str,
    evaluation: &Evaluation,
    timing: Timing,
    breaker: &CircuitBreakerReport,
    loop_report: &LoopGuardReport,
) -> String {
    let mut out = match timing {
        Timing::Prevented => format!("vord blocked this write to `{path}`.\n\n"),
        Timing::AlreadyWritten => {
            format!(
                "vord policy violation in `{path}` — this file has ALREADY been written to disk.\n\n"
            )
        }
    };
    for (index, violation) in evaluation.denials().enumerate() {
        out.push_str(&format!("  {}. {}\n", index + 1, violation.describe()));
    }
    let warnings: Vec<_> = evaluation.warnings().collect();
    if !warnings.is_empty() {
        out.push_str("\nAlso noted (not blocking):\n");
        for violation in warnings {
            out.push_str(&format!("  - {}\n", violation.describe()));
        }
    }
    out.push_str(match timing {
        Timing::Prevented => {
            "\nThis is an Agent Permission Policy block from vord-policy.toml, not a style \
             preference. The file was NOT written. Rewrite the code so these findings do not \
             occur, then write it again. Do not retry the same content, and do not disable \
             the policy.\n"
        }
        Timing::AlreadyWritten => {
            "\nThis is an Agent Permission Policy violation from vord-policy.toml, not a style \
             preference. The offending content is on disk now — fix it before doing anything \
             else, and do not disable the policy.\n"
        }
    });
    if let Some(token) = escalation_token(path, evaluation) {
        out.push_str(&format!(
            "\nThis includes finding(s) that require human approval before they may proceed. A human \
             reviewer must run `vord hook approve {token}` after reviewing this change; only then may \
             you retry the identical write.\n"
        ));
    }
    if breaker.is_tripped() {
        let rules: Vec<&str> = breaker.tripped.iter().map(RuleId::as_str).collect();
        out.push_str(&format!(
            "\nCIRCUIT BREAKER TRIPPED for {}: denied {} times in a row for the same rule. STOP — do not \
             attempt this fix again. Revert your changes to `{path}` and ask a human to review before \
             continuing.\n",
            rules.join(", "),
            CircuitBreakerState::TRIP_THRESHOLD,
        ));
    }
    if loop_report.is_tripped() {
        out.push_str(&format!(
            "\nLOOP ALARM: this exact write (same file, byte-identical content) has now been attempted {} \
             times in a row. Retrying it again will not change the outcome — stop, try a materially \
             different approach, or ask a human for help.\n",
            loop_report.count,
        ));
    }
    out.push_str(&format!(
        "\nMachine-readable form:\n{}\n",
        serde_json::to_string(&structured_report(path, evaluation, breaker, loop_report))
            .unwrap_or_default(),
    ));
    out
}

/// The non-blocking counterpart: findings worth putting in front of the model
/// without stopping it.
pub fn advisory_text(path: &str, evaluation: &Evaluation, loop_report: &LoopGuardReport) -> String {
    let mut out = format!("vord found issues in `{path}`:\n\n");
    for violation in &evaluation.violations {
        out.push_str(&format!("  - {}\n", violation.describe()));
    }
    out.push_str("\nConsider fixing these before moving on.\n");
    if loop_report.is_tripped() {
        out.push_str(&format!(
            "\nLOOP ALARM: this exact write (same file, byte-identical content) has now been attempted {} \
             times in a row.\n",
            loop_report.count,
        ));
    }
    out
}

// ---------------------------------------------------------------------------
// Claude Code adapter
// ---------------------------------------------------------------------------

/// Builds the JSON Claude Code expects on stdout for a given verdict.
///
/// `PreToolUse` emits a denial or *nothing at all*. Emitting
/// `permissionDecision: "allow"` on the non-denied path would be actively
/// harmful — it would override the user's own permission settings and
/// auto-approve every edit vord happens not to object to, turning a security
/// tool into a permission bypass. Staying silent lets the host's normal
/// permission flow run untouched.
pub fn claude_code_output(
    event: &str,
    verdict: &Verdict,
    breaker: &CircuitBreakerReport,
    loop_report: &LoopGuardReport,
) -> Option<serde_json::Value> {
    match (event, verdict) {
        (_, Verdict::Silent) => None,
        ("PreToolUse", Verdict::Deny { path, evaluation }) => Some(serde_json::json!({
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": denial_text(path, evaluation, Timing::Prevented, breaker, loop_report),
            }
        })),
        // Pre-write advisories are deliberately dropped: the only way to
        // attach them here is alongside an `allow`, and see above.
        ("PreToolUse", Verdict::Advise { .. }) => None,
        ("PostToolUse", Verdict::Deny { path, evaluation }) => Some(serde_json::json!({
            "decision": "block",
            "reason": denial_text(path, evaluation, Timing::AlreadyWritten, breaker, loop_report),
        })),
        ("PostToolUse", Verdict::Advise { path, evaluation }) => Some(serde_json::json!({
            "hookSpecificOutput": {
                "hookEventName": "PostToolUse",
                "additionalContext": advisory_text(path, evaluation, loop_report),
            }
        })),
        _ => None,
    }
}

/// `vord hook claude-code`: reads the hook payload on stdin, writes the
/// verdict JSON on stdout, always exits 0.
///
/// Exit 0 with a JSON body is the documented way to deny; exit 2 also denies
/// but forces the reason through stderr, losing the structured form. Using
/// the JSON path uniformly means one code path for both events.
pub async fn run_claude_code() -> anyhow::Result<std::process::ExitCode> {
    let mut raw = String::new();
    std::io::stdin().read_to_string(&mut raw)?;

    let (verdict, loop_report) = match claude_code_verdict(&raw).await {
        Ok(result) => result,
        Err(e) => {
            // Fail open: the agent keeps working, the operator sees why.
            eprintln!("vord hook: {e:#}");
            return Ok(std::process::ExitCode::SUCCESS);
        }
    };

    let payload: HookPayload = serde_json::from_str(&raw).unwrap_or(HookPayload {
        hook_event_name: String::new(),
        tool_name: String::new(),
        tool_input: serde_json::Value::Null,
        cwd: None,
    });
    let root = payload
        .cwd
        .as_ref()
        .map(PathBuf::from)
        .or_else(|| std::env::current_dir().ok())
        .unwrap_or_else(|| PathBuf::from("."));
    let breaker = track_circuit_breaker(&root, &verdict);
    append_audit_log(
        &root,
        &payload.hook_event_name,
        &verdict,
        &breaker,
        &loop_report,
    );
    if let Some(output) =
        claude_code_output(&payload.hook_event_name, &verdict, &breaker, &loop_report)
    {
        println!("{}", serde_json::to_string(&output)?);
    }
    Ok(std::process::ExitCode::SUCCESS)
}

/// The analysable half of the Claude Code hook, split out so the wiring
/// above stays a thin shell around a function that can be tested. Also
/// tracks the loop alarm — it needs the same `(root, relative path,
/// content)` this function already assembles for `judge`, so it is folded in
/// here rather than re-derived by the caller.
async fn claude_code_verdict(raw: &str) -> anyhow::Result<(Verdict, LoopGuardReport)> {
    let payload: HookPayload =
        serde_json::from_str(raw).map_err(|e| anyhow::anyhow!("bad hook payload: {e}"))?;

    let Some(file_path) = payload.tool_input.get("file_path").and_then(|v| v.as_str()) else {
        return Ok((Verdict::Silent, LoopGuardReport::default()));
    };
    let file = PathBuf::from(file_path);
    let root = payload
        .cwd
        .as_ref()
        .map(PathBuf::from)
        .or_else(|| std::env::current_dir().ok())
        .unwrap_or_else(|| PathBuf::from("."));

    let policy = load_policy(&root)?;
    if !policy.enabled() {
        return Ok((Verdict::Silent, LoopGuardReport::default()));
    }

    // Pre-write: judge what the agent is about to write. Post-write: it is
    // already on disk, so disk is the truth.
    let content = match payload.hook_event_name.as_str() {
        "PreToolUse" => proposed_content(&payload.tool_name, &payload.tool_input, &file),
        _ => std::fs::read_to_string(&file).ok(),
    };

    let relative = relative_to(&root, &file);
    let loop_report = track_loop_guard(&root, &relative, content.as_deref());
    let verdict = judge(&policy, &root, &file, content.as_deref()).await?;
    Ok((verdict, loop_report))
}

// ---------------------------------------------------------------------------
// Portable adapter
// ---------------------------------------------------------------------------

/// `vord hook check <file>`: the host-agnostic gate.
///
/// Exit codes are the contract here, since there is no host to speak JSON to:
/// `0` allowed, `2` denied by policy, `1` vord itself failed. Callers that
/// must not be blocked by a vord bug can treat 1 as success; callers that
/// want strictness can treat it as failure. Both are possible only because
/// the two are distinguishable.
pub async fn run_check(
    file: PathBuf,
    format: HookOutputFormat,
) -> anyhow::Result<std::process::ExitCode> {
    let root = std::env::current_dir()?;
    let policy = load_policy(&root)?;
    if !policy.enabled() {
        return Ok(std::process::ExitCode::SUCCESS);
    }

    let content = std::fs::read_to_string(&file).ok();
    let relative = relative_to(&root, &file);
    let loop_report = track_loop_guard(&root, &relative, content.as_deref());
    let verdict = judge(&policy, &root, &file, content.as_deref()).await?;
    let breaker = track_circuit_breaker(&root, &verdict);
    append_audit_log(&root, "check", &verdict, &breaker, &loop_report);

    match verdict {
        Verdict::Silent => Ok(std::process::ExitCode::SUCCESS),
        Verdict::Advise { path, evaluation } => {
            match format {
                HookOutputFormat::Json => println!(
                    "{}",
                    serde_json::to_string_pretty(&structured_report(
                        &path,
                        &evaluation,
                        &breaker,
                        &loop_report
                    ))?
                ),
                HookOutputFormat::Text => {
                    eprintln!("{}", advisory_text(&path, &evaluation, &loop_report))
                }
            }
            Ok(std::process::ExitCode::SUCCESS)
        }
        Verdict::Deny { path, evaluation } => {
            // `check` judges a file that exists, so the write has landed by
            // definition — even when the caller is a pre-commit hook about
            // to reject the commit that carries it.
            match format {
                HookOutputFormat::Json => println!(
                    "{}",
                    serde_json::to_string_pretty(&structured_report(
                        &path,
                        &evaluation,
                        &breaker,
                        &loop_report
                    ))?
                ),
                HookOutputFormat::Text => {
                    eprintln!(
                        "{}",
                        denial_text(
                            &path,
                            &evaluation,
                            Timing::AlreadyWritten,
                            &breaker,
                            &loop_report
                        )
                    )
                }
            }
            Ok(std::process::ExitCode::from(2))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_write_tool_call_yields_its_own_content() {
        let input = serde_json::json!({ "file_path": "/tmp/a.ts", "content": "const a = 1;" });
        assert_eq!(
            proposed_content("Write", &input, Path::new("/nonexistent")).as_deref(),
            Some("const a = 1;")
        );
    }

    #[test]
    fn an_edit_tool_call_is_applied_to_the_file_on_disk() {
        let dir = std::env::temp_dir().join(format!("vord-hook-edit-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let file = dir.join("a.ts");
        std::fs::write(&file, "const a = 1;\nconst b = 1;\n").expect("write");

        let input = serde_json::json!({ "old_string": "1", "new_string": "2" });
        assert_eq!(
            proposed_content("Edit", &input, &file).as_deref(),
            Some("const a = 2;\nconst b = 1;\n"),
            "a non-replace_all edit must replace only the first occurrence, as the host does"
        );

        let all = serde_json::json!({ "old_string": "1", "new_string": "2", "replace_all": true });
        assert_eq!(
            proposed_content("Edit", &all, &file).as_deref(),
            Some("const a = 2;\nconst b = 2;\n")
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn an_unrecognized_tool_yields_no_content_rather_than_a_guess() {
        let input = serde_json::json!({ "file_path": "/tmp/a.ipynb", "new_source": "x = 1" });
        assert!(proposed_content("NotebookEdit", &input, Path::new("/tmp/a.ipynb")).is_none());
    }

    #[test]
    fn an_absolute_tool_path_is_rebased_onto_the_repository_root() {
        assert_eq!(
            relative_to(Path::new("/repo"), Path::new("/repo/src/a.ts")),
            "src/a.ts"
        );
    }

    #[test]
    fn a_path_outside_the_root_still_produces_a_relative_form() {
        // `SourceFile` rejects absolute paths outright, so leaking one here
        // would turn an out-of-tree edit into a hard error instead of a
        // judgement.
        assert_eq!(
            relative_to(Path::new("/repo"), Path::new("/etc/passwd")),
            "etc/passwd"
        );
    }

    #[tokio::test]
    async fn a_file_with_no_known_extension_analyses_to_no_findings() {
        assert!(
            analyze_content(Path::new("/repo"), "notes.unknownext", "whatever")
                .await
                .expect("ok")
                .is_empty()
        );
    }

    #[tokio::test]
    async fn a_real_vulnerability_in_proposed_content_is_found() {
        let findings = analyze_content(
            Path::new("/repo"),
            "app.py",
            "import subprocess\nsubprocess.run(cmd, shell=True)\n",
        )
        .await
        .expect("analysis runs");
        assert!(
            findings
                .iter()
                .any(|f| f.rule.as_str() == "python:subprocess-shell-true"),
            "expected shell=True to be found, got {findings:?}"
        );
    }

    #[tokio::test]
    async fn a_hotspot_rule_is_included_in_analyze_content_findings() {
        // `owasp:command-execution` is `FindingKind::Hotspot`, not `Issue` —
        // it must still reach the agent policy, or the shipped default
        // `blocking_rules` entry naming it can never actually deny anything.
        let findings = analyze_content(
            Path::new("/repo"),
            "app.py",
            "import os\nos.system(user_input)\n",
        )
        .await
        .expect("analysis runs");
        assert!(
            findings
                .iter()
                .any(|f| f.rule.as_str() == "owasp:command-execution"),
            "hotspot-classified rules must still reach the agent policy, got {findings:?}"
        );
    }

    /// Sets up a throwaway directory under the OS temp dir (no `tempfile`
    /// dependency in this crate) with `src/main.rs` containing one axum
    /// route and, when `covering_test` is `Some`, a `tests/covers.rs`
    /// referencing that exact route path — the two-file shape the reported
    /// bug needed to reproduce, since `rust:route-without-test-coverage`
    /// only sees coverage that lives in a *different* file from the route.
    fn cross_file_route_fixture(test_name: &str, covering_test: Option<&str>) -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "vord-hook-cross-file-test-{test_name}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("src")).unwrap();
        if let Some(test_body) = covering_test {
            std::fs::create_dir_all(root.join("tests")).unwrap();
            std::fs::write(root.join("tests/covers.rs"), test_body).unwrap();
        }
        root
    }

    #[tokio::test]
    async fn a_route_covered_only_by_a_separate_test_file_is_not_flagged() {
        // Regression test: `analyze_content` used to hand the engine only
        // the one file being judged, so `rust:route-without-test-coverage`
        // (a `CrossFileRule`) could never see a covering test that lives in
        // a different file — denying writes a full `vord scan .` (which
        // does load the whole project) passes clean.
        let root = cross_file_route_fixture(
            "covered",
            Some("#[test]\nfn hits_it() {\n    client.get(\"/api/v1/widgets\").send();\n}\n"),
        );
        let content = "fn app() -> Router {\n    Router::new()\n        .route(\"/api/v1/widgets\", get(list_widgets))\n}\n";
        let findings = analyze_content(&root, "src/main.rs", content)
            .await
            .expect("analysis runs");
        std::fs::remove_dir_all(&root).ok();
        assert!(
            !findings
                .iter()
                .any(|f| f.rule.as_str() == "rust:route-without-test-coverage"),
            "route covered by a separate test file must not be flagged, got {findings:?}"
        );
    }

    #[tokio::test]
    async fn a_route_with_no_test_anywhere_in_the_project_is_still_flagged() {
        // The other half of the same fix: pulling in the rest of the
        // project must not swallow a genuinely uncovered route.
        let root = cross_file_route_fixture("uncovered", None);
        let content = "fn app() -> Router {\n    Router::new()\n        .route(\"/api/v1/widgets\", get(list_widgets))\n}\n";
        let findings = analyze_content(&root, "src/main.rs", content)
            .await
            .expect("analysis runs");
        std::fs::remove_dir_all(&root).ok();
        assert!(
            findings
                .iter()
                .any(|f| f.rule.as_str() == "rust:route-without-test-coverage"),
            "route with no test anywhere must still be flagged, got {findings:?}"
        );
    }

    #[tokio::test]
    async fn the_built_in_default_policy_actually_denies_a_hotspot_blocking_rule() {
        // Regression test for the bug this session fixed: `analyze_content`
        // used to map only `report.issues()`, so `AgentPolicy::default()`'s
        // own built-in `blocking_rules` (which names `owasp:command-execution`,
        // a hotspot-only rule) silently never denied anything for it — the
        // README's flagship "shell-injection sink gets denied" example was
        // not actually true out of the box.
        let policy = AgentPolicy::default();
        let root = Path::new("/repo");
        let verdict = judge(
            &policy,
            root,
            Path::new("/repo/app.py"),
            Some("import os\nos.system(user_input)\n"),
        )
        .await
        .expect("judged");
        assert!(matches!(verdict, Verdict::Deny { .. }), "got {verdict:?}");
    }

    #[tokio::test]
    async fn a_blocking_rule_in_proposed_content_denies_before_the_file_exists() {
        let policy = AgentPolicy::default();
        let root = Path::new("/repo");
        // Note the file genuinely does not exist: this is the whole premise
        // of PreToolUse gating.
        let verdict = judge(
            &policy,
            root,
            Path::new("/repo/app.py"),
            Some("import subprocess\nsubprocess.run(cmd, shell=True)\n"),
        )
        .await
        .expect("judged");
        assert!(matches!(verdict, Verdict::Deny { .. }), "got {verdict:?}");
    }

    #[tokio::test]
    async fn clean_content_stays_silent() {
        let policy = AgentPolicy::default();
        let verdict = judge(
            &policy,
            Path::new("/repo"),
            Path::new("/repo/a.py"),
            Some("x = 1\n"),
        )
        .await
        .expect("judged");
        assert!(matches!(verdict, Verdict::Silent), "got {verdict:?}");
    }

    #[test]
    fn pre_tool_use_emits_a_deny_decision() {
        let evaluation = AgentPolicy::default().evaluate(
            "a.py",
            &[Finding {
                rule: vord_rules_engine::RuleId::new("owasp:eval-usage").expect("rule"),
                severity: vord_rules_engine::Severity::Blocker,
                message: "eval".to_string(),
                line: 3,
            }],
        );
        let verdict = Verdict::from_evaluation("a.py".to_string(), evaluation);
        let output = claude_code_output(
            "PreToolUse",
            &verdict,
            &CircuitBreakerReport::default(),
            &LoopGuardReport::default(),
        )
        .expect("emits");
        assert_eq!(output["hookSpecificOutput"]["permissionDecision"], "deny");
        let reason = output["hookSpecificOutput"]["permissionDecisionReason"]
            .as_str()
            .expect("reason");
        assert!(reason.contains("owasp:eval-usage"), "{reason}");
        assert!(reason.contains("line 3"), "{reason}");
    }

    #[test]
    fn post_tool_use_blocks_with_a_reason_instead_of_a_permission_decision() {
        let evaluation = AgentPolicy::default().evaluate(
            "a.py",
            &[Finding {
                rule: vord_rules_engine::RuleId::new("owasp:eval-usage").expect("rule"),
                severity: vord_rules_engine::Severity::Blocker,
                message: "eval".to_string(),
                line: 3,
            }],
        );
        let verdict = Verdict::from_evaluation("a.py".to_string(), evaluation);
        let output = claude_code_output(
            "PostToolUse",
            &verdict,
            &CircuitBreakerReport::default(),
            &LoopGuardReport::default(),
        )
        .expect("emits");
        assert_eq!(output["decision"], "block");
        assert!(
            output["reason"]
                .as_str()
                .expect("reason")
                .contains("owasp:eval-usage")
        );
    }

    #[test]
    fn the_two_events_disagree_about_whether_the_file_was_written() {
        // The model acts on this sentence. Telling it "blocked, not written"
        // after a PostToolUse — where the bytes are already on disk — makes
        // it move on and leave the finding in the tree.
        let evaluation = AgentPolicy::default().evaluate(
            "a.py",
            &[Finding {
                rule: vord_rules_engine::RuleId::new("owasp:eval-usage").expect("rule"),
                severity: vord_rules_engine::Severity::Blocker,
                message: "eval".to_string(),
                line: 3,
            }],
        );

        let breaker = CircuitBreakerReport::default();
        let loop_report = LoopGuardReport::default();
        let prevented = denial_text(
            "a.py",
            &evaluation,
            Timing::Prevented,
            &breaker,
            &loop_report,
        );
        assert!(prevented.contains("was NOT written"), "{prevented}");

        let landed = denial_text(
            "a.py",
            &evaluation,
            Timing::AlreadyWritten,
            &breaker,
            &loop_report,
        );
        assert!(landed.contains("ALREADY been written"), "{landed}");
        assert!(!landed.contains("was NOT written"), "{landed}");
    }

    #[test]
    fn a_silent_verdict_emits_nothing_on_either_event() {
        let breaker = CircuitBreakerReport::default();
        let loop_report = LoopGuardReport::default();
        assert!(
            claude_code_output("PreToolUse", &Verdict::Silent, &breaker, &loop_report).is_none()
        );
        assert!(
            claude_code_output("PostToolUse", &Verdict::Silent, &breaker, &loop_report).is_none()
        );
    }

    #[test]
    fn pre_tool_use_never_emits_allow_for_an_advisory() {
        // Regression guard for a permission bypass: emitting `allow` here
        // would auto-approve every edit vord does not object to.
        let evaluation = AgentPolicy::parse("[agent]\nadvisory_rules = [\"owasp:eval-usage\"]\n")
            .expect("parses")
            .evaluate(
                "a.py",
                &[Finding {
                    rule: vord_rules_engine::RuleId::new("owasp:eval-usage").expect("rule"),
                    severity: vord_rules_engine::Severity::Blocker,
                    message: "eval".to_string(),
                    line: 3,
                }],
            );
        let verdict = Verdict::from_evaluation("a.py".to_string(), evaluation);
        assert!(matches!(verdict, Verdict::Advise { .. }));
        assert!(
            claude_code_output(
                "PreToolUse",
                &verdict,
                &CircuitBreakerReport::default(),
                &LoopGuardReport::default()
            )
            .is_none()
        );
    }

    #[tokio::test]
    async fn a_malformed_payload_is_an_error_that_the_caller_fails_open_on() {
        assert!(claude_code_verdict("not json at all").await.is_err());
    }

    #[tokio::test]
    async fn a_payload_with_no_file_path_is_silent() {
        let raw =
            r#"{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"ls"}}"#;
        let (verdict, _loop_report) = claude_code_verdict(raw).await.expect("ok");
        assert!(matches!(verdict, Verdict::Silent));
    }

    fn eval_usage_evaluation() -> Evaluation {
        AgentPolicy::default().evaluate(
            "a.py",
            &[Finding {
                rule: RuleId::new("owasp:eval-usage").expect("rule"),
                severity: vord_rules_engine::Severity::Blocker,
                message: "eval".to_string(),
                line: 3,
            }],
        )
    }

    #[test]
    fn structured_report_names_the_rule_line_and_expected_state() {
        let evaluation = eval_usage_evaluation();
        let report = structured_report(
            "a.py",
            &evaluation,
            &CircuitBreakerReport::default(),
            &LoopGuardReport::default(),
        );
        assert_eq!(report["path"], "a.py");
        assert_eq!(report["denied"], true);
        assert_eq!(report["circuit_breaker_tripped"], false);
        let violation = &report["violations"][0];
        assert_eq!(violation["rule"], "owasp:eval-usage");
        assert_eq!(violation["line"], 3);
        assert_eq!(violation["enforcement"], "deny");
        assert_eq!(violation["cause"], "blocking_rule");
        assert!(
            violation["expected_state"]
                .as_str()
                .expect("state")
                .contains("owasp:eval-usage")
        );
    }

    #[test]
    fn a_protected_path_violation_has_no_rule_in_the_structured_report() {
        let policy = AgentPolicy::parse(
            "[[protected_path]]\npattern = \".github/workflows/**\"\nreason = \"CI.\"\n",
        )
        .expect("parses");
        let evaluation = policy.evaluate(".github/workflows/ci.yml", &[]);
        let report = structured_report(
            ".github/workflows/ci.yml",
            &evaluation,
            &CircuitBreakerReport::default(),
            &LoopGuardReport::default(),
        );
        let violation = &report["violations"][0];
        assert_eq!(violation["rule"], serde_json::Value::Null);
        assert_eq!(violation["cause"], "protected_path");
    }

    #[test]
    fn denial_text_embeds_a_parseable_machine_readable_block() {
        let evaluation = eval_usage_evaluation();
        let text = denial_text(
            "a.py",
            &evaluation,
            Timing::Prevented,
            &CircuitBreakerReport::default(),
            &LoopGuardReport::default(),
        );
        let json_line = text.lines().last().expect("a line");
        let parsed: serde_json::Value = serde_json::from_str(json_line).expect("valid json");
        assert_eq!(parsed["violations"][0]["rule"], "owasp:eval-usage");
    }

    #[test]
    fn a_tripped_breaker_adds_a_stop_and_rollback_instruction() {
        let evaluation = eval_usage_evaluation();
        let breaker = CircuitBreakerReport {
            tripped: vec![RuleId::new("owasp:eval-usage").expect("rule")],
        };
        let text = denial_text(
            "a.py",
            &evaluation,
            Timing::Prevented,
            &breaker,
            &LoopGuardReport::default(),
        );
        assert!(text.contains("CIRCUIT BREAKER TRIPPED"), "{text}");
        assert!(text.contains("Revert"), "{text}");
        assert!(text.to_lowercase().contains("human"), "{text}");
    }

    #[test]
    fn a_verdict_without_a_tripped_rule_adds_no_stop_instruction() {
        let evaluation = eval_usage_evaluation();
        let text = denial_text(
            "a.py",
            &evaluation,
            Timing::Prevented,
            &CircuitBreakerReport::default(),
            &LoopGuardReport::default(),
        );
        assert!(!text.contains("CIRCUIT BREAKER"), "{text}");
    }

    #[test]
    fn a_tripped_loop_alarm_adds_a_stop_instruction() {
        let evaluation = eval_usage_evaluation();
        let text = denial_text(
            "a.py",
            &evaluation,
            Timing::Prevented,
            &CircuitBreakerReport::default(),
            &LoopGuardReport { count: 3 },
        );
        assert!(text.contains("LOOP ALARM"), "{text}");
        assert!(text.contains('3'), "{text}");
    }

    #[test]
    fn an_untripped_loop_guard_adds_no_alarm_text() {
        let evaluation = eval_usage_evaluation();
        let text = denial_text(
            "a.py",
            &evaluation,
            Timing::Prevented,
            &CircuitBreakerReport::default(),
            &LoopGuardReport { count: 1 },
        );
        assert!(!text.contains("LOOP ALARM"), "{text}");
    }

    #[test]
    fn identical_writes_trip_the_loop_alarm_on_the_third_repeat() {
        let dir = std::env::temp_dir().join(format!("vord-hook-loop-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");

        assert!(!track_loop_guard(&dir, "a.py", Some("x = 1")).is_tripped());
        assert!(!track_loop_guard(&dir, "a.py", Some("x = 1")).is_tripped());
        let third = track_loop_guard(&dir, "a.py", Some("x = 1"));
        assert!(
            third.is_tripped(),
            "the third identical write in a row must trip the alarm"
        );
        assert_eq!(third.count, 3);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_write_that_changes_content_resets_the_loop_streak() {
        let dir = std::env::temp_dir().join(format!("vord-hook-loop-reset-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");

        track_loop_guard(&dir, "a.py", Some("x = 1"));
        track_loop_guard(&dir, "a.py", Some("x = 1"));
        let changed = track_loop_guard(&dir, "a.py", Some("x = 2"));
        assert_eq!(changed.count, 1, "different content is not the same write");
        assert!(!changed.is_tripped());

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn reset_loop_guard_clears_the_persisted_streak() {
        let dir = std::env::temp_dir().join(format!("vord-hook-loop-clear-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");

        track_loop_guard(&dir, "a.py", Some("x = 1"));
        track_loop_guard(&dir, "a.py", Some("x = 1"));
        reset_loop_guard(&dir).expect("reset");
        let after = track_loop_guard(&dir, "a.py", Some("x = 1"));
        assert_eq!(after.count, 1, "reset clears the persisted streak");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn the_circuit_breaker_state_persists_across_separate_invocations() {
        let dir = std::env::temp_dir().join(format!("vord-hook-breaker-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");

        let verdict = Verdict::from_evaluation("a.py".to_string(), eval_usage_evaluation());

        assert!(!track_circuit_breaker(&dir, &verdict).is_tripped());
        assert!(!track_circuit_breaker(&dir, &verdict).is_tripped());
        let third = track_circuit_breaker(&dir, &verdict);
        assert!(
            third.is_tripped(),
            "the third consecutive denial of the same rule must trip"
        );
        assert_eq!(
            third.tripped,
            vec![RuleId::new("owasp:eval-usage").expect("rule")]
        );

        reset_circuit_breaker(&dir).expect("reset");
        assert!(
            !track_circuit_breaker(&dir, &verdict).is_tripped(),
            "reset clears the persisted streak"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_clean_write_resets_the_persisted_streak() {
        let dir =
            std::env::temp_dir().join(format!("vord-hook-breaker-reset-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");

        let denied = Verdict::from_evaluation("a.py".to_string(), eval_usage_evaluation());
        track_circuit_breaker(&dir, &denied);
        track_circuit_breaker(&dir, &denied);

        track_circuit_breaker(&dir, &Verdict::Silent);
        let third = track_circuit_breaker(&dir, &denied);
        assert!(
            !third.is_tripped(),
            "the silent write in between broke the streak"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_new_dependency_in_package_json_is_flagged() {
        let old = r#"{"dependencies": {"left-pad": "1.0.0"}}"#;
        let new = r#"{"dependencies": {"left-pad": "1.0.0", "left-pad-plus": "0.0.1"}}"#;
        let findings = new_dependency_findings("package.json", Some(old), new);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule.as_str(), "supply-chain:new-dependency");
        assert!(
            findings[0].message.contains("left-pad-plus"),
            "{}",
            findings[0].message
        );
    }

    #[test]
    fn removing_or_pinning_a_dependency_in_package_json_flags_nothing() {
        let old = r#"{"dependencies": {"left-pad": "1.0.0"}}"#;
        let same_set = r#"{"dependencies": {"left-pad": "1.0.1"}}"#;
        assert!(new_dependency_findings("package.json", Some(old), same_set).is_empty());
    }

    #[test]
    fn a_brand_new_package_json_flags_nothing() {
        let new = r#"{"dependencies": {"left-pad": "1.0.0"}}"#;
        assert!(
            new_dependency_findings("package.json", None, new).is_empty(),
            "bootstrapping a project's first dependency set is not drift"
        );
    }

    #[test]
    fn a_new_dependency_in_requirements_txt_is_flagged() {
        let old = "flask==2.0.0\n# a comment\n";
        let new = "flask==2.0.0\nrequests>=2.31.0\n";
        let findings = new_dependency_findings("requirements.txt", Some(old), new);
        assert_eq!(findings.len(), 1);
        assert!(
            findings[0].message.contains("requests"),
            "{}",
            findings[0].message
        );
    }

    #[test]
    fn an_unrelated_file_is_never_diffed_for_dependencies() {
        assert!(new_dependency_findings("src/app.py", Some("x = 1"), "x = 2").is_empty());
    }

    #[test]
    fn a_newly_added_allow_attribute_is_flagged() {
        let old = "fn risky() {\n    x.unwrap();\n}\n";
        let new = "#[allow(clippy::unwrap_used)]\nfn risky() {\n    x.unwrap();\n}\n";
        let findings = suppression_added_findings("src/lib.rs", Some(old), new);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule.as_str(), "ai:suppression-added");
        assert!(
            findings[0]
                .message
                .contains("#[allow(clippy::unwrap_used)]"),
            "{}",
            findings[0].message
        );
    }

    #[test]
    fn a_pre_existing_allow_attribute_is_not_re_flagged() {
        let content = "#[allow(dead_code)]\nfn unused() {}\n";
        assert!(suppression_added_findings("src/lib.rs", Some(content), content).is_empty());
    }

    #[test]
    fn every_suppression_in_a_brand_new_file_is_flagged() {
        // Unlike a brand-new manifest's dependency set, a suppression in a
        // file that did not exist before was still, in fact, added by this
        // write — there is no "this file always had it" case to protect.
        let new = "# noqa: E501\nprint('x' * 1000)\n";
        let findings = suppression_added_findings("scratch.py", None, new);
        assert_eq!(findings.len(), 1);
        assert!(
            findings[0].message.contains("# noqa"),
            "{}",
            findings[0].message
        );
    }

    #[test]
    fn a_coverage_exclusion_pragma_is_flagged() {
        let old = "def untested():\n    pass\n";
        let new = "def untested():  # pragma: no cover\n    pass\n";
        let findings = suppression_added_findings("app.py", Some(old), new);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule.as_str(), "ai:suppression-added");
    }

    #[test]
    fn a_newly_ignored_rust_test_is_flagged() {
        let old = "#[test]\nfn it_works() {\n    assert!(true);\n}\n";
        let new = "#[test]\n#[ignore]\nfn it_works() {\n    assert!(true);\n}\n";
        let findings = test_skip_added_findings("src/lib.rs", Some(old), new);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule.as_str(), "ai:test-skipped");
        assert!(
            findings[0].message.contains("#[ignore]"),
            "{}",
            findings[0].message
        );
    }

    #[test]
    fn a_newly_skipped_jest_test_is_flagged() {
        let old = "it('adds', () => { expect(1 + 1).toBe(2); });\n";
        let new = "it.skip('adds', () => { expect(1 + 1).toBe(2); });\n";
        let findings = test_skip_added_findings("app.test.ts", Some(old), new);
        assert_eq!(findings.len(), 1);
        assert!(
            findings[0].message.contains(".skip("),
            "{}",
            findings[0].message
        );
    }

    #[test]
    fn a_pre_existing_ignore_is_not_re_flagged() {
        let content = "#[test]\n#[ignore]\nfn flaky() {}\n";
        assert!(test_skip_added_findings("src/lib.rs", Some(content), content).is_empty());
    }

    const REAL_SCENARIO: &str = "\
@covers(core/domain/**)
Feature: Orders

  Scenario: Checkout
    Given a cart
    When I check out
    Then the order is placed
";

    #[test]
    fn a_covers_tag_over_an_empty_feature_is_flagged_as_unverified() {
        let findings = bdd_feature_findings(
            "features/orders.feature",
            None,
            "@covers(core/domain/**)\nFeature: Orders\n",
        );
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule.as_str(), "bdd:unverified-scenario");
        assert_eq!(findings[0].line, 1);
        assert!(
            findings[0].message.contains("core/domain/**"),
            "{}",
            findings[0].message
        );
    }

    #[test]
    fn a_real_scenario_is_not_flagged() {
        assert!(bdd_feature_findings("features/orders.feature", None, REAL_SCENARIO).is_empty());
    }

    #[test]
    fn an_overbroad_covers_glob_is_flagged_under_its_own_rule() {
        let content = REAL_SCENARIO.replace("core/domain/**", "**");
        let findings = bdd_feature_findings("features/orders.feature", None, &content);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule.as_str(), "bdd:overbroad-covers");
    }

    #[test]
    fn a_non_feature_file_is_never_scanned_for_covers_claims() {
        // The tag text can legitimately appear in prose or in this very
        // module's own documentation; only `.feature` files make a claim.
        assert!(bdd_feature_findings("README.md", None, "@covers(**)\nFeature: x\n").is_empty());
    }

    #[test]
    fn a_pre_existing_unverified_claim_is_not_re_flagged() {
        let old = "@covers(core/domain/**)\nFeature: Orders\n";
        let new = format!("{old}\n  Scenario: A start\n    Given a cart\n");
        assert!(bdd_feature_findings("features/orders.feature", Some(old), &new).is_empty());
    }

    #[tokio::test]
    async fn an_unbacked_covers_claim_is_wired_into_the_full_judge_pipeline() {
        let dir = std::env::temp_dir().join(format!("vord-hook-bdd-claim-{}", std::process::id()));
        std::fs::create_dir_all(dir.join("features")).expect("temp dir");
        let file = dir.join("features/orders.feature");

        let policy =
            AgentPolicy::parse("[agent]\nblocking_rules = [\"bdd:unverified-scenario\"]\n")
                .expect("parses");
        let verdict = judge(
            &policy,
            &dir,
            &file,
            Some("@covers(core/domain/**)\nFeature: Orders\n"),
        )
        .await
        .expect("judged");
        assert!(
            matches!(verdict, Verdict::Deny { .. }),
            "an opted-in repository denies the claim, got {verdict:?}"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn a_new_suppression_is_wired_into_the_full_judge_pipeline() {
        let dir =
            std::env::temp_dir().join(format!("vord-hook-suppression-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let file = dir.join("lib.rs");
        std::fs::write(&file, "fn f() {}\n").expect("write");

        let policy = AgentPolicy::parse("[agent]\nblocking_rules = [\"ai:suppression-added\"]\n")
            .expect("parses");
        let new_content = "#[allow(dead_code)]\nfn f() {}\n";
        let verdict = judge(&policy, &dir, &file, Some(new_content))
            .await
            .expect("judged");
        assert!(matches!(verdict, Verdict::Deny { .. }), "got {verdict:?}");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn a_new_dependency_is_wired_into_the_full_judge_pipeline() {
        let dir = std::env::temp_dir().join(format!("vord-hook-manifest-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let manifest = dir.join("package.json");
        std::fs::write(&manifest, r#"{"dependencies": {"left-pad": "1.0.0"}}"#).expect("write");

        // Not blocked by the *default* policy (Major is below the default
        // `critical` threshold) — an install opts in explicitly, exactly as
        // it would for any other rule id.
        let policy =
            AgentPolicy::parse("[agent]\nblocking_rules = [\"supply-chain:new-dependency\"]\n")
                .expect("parses");
        let new_content = r#"{"dependencies": {"left-pad": "1.0.0", "left-pad-plus": "0.0.1"}}"#;
        let verdict = judge(&policy, &dir, &manifest, Some(new_content))
            .await
            .expect("judged");
        assert!(matches!(verdict, Verdict::Deny { .. }), "got {verdict:?}");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn preexisting_whole_file_metric_findings_are_dropped_but_new_ones_kept() {
        let mi = RuleId::new("smells:maintainability-index").unwrap();
        let wmc = RuleId::new("smells:ck-oo-metrics").unwrap();
        let long_fn = RuleId::new("smells:long-function").unwrap();

        // Same rule already fired before this write — the message's own
        // score has drifted (18.0 -> 17.5), the ordinary "unrelated edit"
        // case, and must not make this look like a new violation.
        let old_findings = vec![Finding {
            rule: mi.clone(),
            severity: vord_rules_engine::Severity::Major,
            message: "Low Maintainability Index: `18.0/100` (threshold = 20.0).".into(),
            line: 1,
        }];

        let mut findings = vec![
            Finding {
                rule: mi.clone(),
                severity: vord_rules_engine::Severity::Major,
                message: "Low Maintainability Index: `17.5/100` (threshold = 20.0).".into(),
                line: 1,
            },
            Finding {
                rule: wmc.clone(),
                severity: vord_rules_engine::Severity::Major,
                message: "CK Metric Violation: high WMC".into(),
                line: 3,
            },
            Finding {
                rule: long_fn.clone(),
                severity: vord_rules_engine::Severity::Minor,
                message: "function spans 60 lines (max 50)".into(),
                line: 10,
            },
        ];

        drop_preexisting_findings(&mut findings, &old_findings);

        let rules: Vec<&str> = findings.iter().map(|f| f.rule.as_str()).collect();
        assert!(
            !rules.contains(&mi.as_str()),
            "the pre-existing MI finding must be dropped, got {rules:?}"
        );
        assert!(
            rules.contains(&wmc.as_str()),
            "a whole-file rule with no prior finding is a genuinely new violation and must stay, got {rules:?}"
        );
        assert!(
            rules.contains(&long_fn.as_str()),
            "a rule with no matching prior finding has nothing to drop and must stay, got {rules:?}"
        );
    }

    #[test]
    fn preexisting_per_function_complexity_findings_survive_an_unrelated_line_shift() {
        // Reproduces the reported bug: a pure comment addition earlier in the
        // file shifts every finding below it down by one line, and a
        // per-function rule's message (unlike the whole-file metrics above)
        // says nothing that identifies *which* function it is about — so a
        // naive (rule, message, line) match would see "new" findings on
        // every single write to a file that has any pre-existing complexity
        // violation anywhere in it.
        let complexity = RuleId::new("smells:high-complexity").unwrap();
        let old_findings = vec![Finding {
            rule: complexity.clone(),
            severity: vord_rules_engine::Severity::Major,
            message: "function has cyclomatic complexity 12 (max 10)".into(),
            line: 40,
        }];

        // Same finding, same message, but three lines lower — as if three
        // comment lines were inserted above it — and nothing else changed.
        let mut findings = vec![Finding {
            rule: complexity.clone(),
            severity: vord_rules_engine::Severity::Major,
            message: "function has cyclomatic complexity 12 (max 10)".into(),
            line: 43,
        }];

        drop_preexisting_findings(&mut findings, &old_findings);

        assert!(
            findings.is_empty(),
            "an unrelated line shift must not turn a pre-existing complexity finding into a new one, got {findings:?}"
        );
    }

    #[test]
    fn a_second_identically_worded_complexity_finding_is_still_new() {
        // Per-function complexity messages don't name the function, so two
        // functions at the same complexity produce byte-identical messages.
        // Only as many occurrences as already existed may be dropped — the
        // extra one is a genuinely new violation and must still block.
        let complexity = RuleId::new("smells:high-complexity").unwrap();
        let message = "function has cyclomatic complexity 12 (max 10)";
        let old_findings = vec![Finding {
            rule: complexity.clone(),
            severity: vord_rules_engine::Severity::Major,
            message: message.into(),
            line: 10,
        }];

        let mut findings = vec![
            Finding {
                rule: complexity.clone(),
                severity: vord_rules_engine::Severity::Major,
                message: message.into(),
                line: 10,
            },
            Finding {
                rule: complexity.clone(),
                severity: vord_rules_engine::Severity::Major,
                message: message.into(),
                line: 55,
            },
        ];

        drop_preexisting_findings(&mut findings, &old_findings);

        assert_eq!(
            findings.len(),
            1,
            "only the previously-existing occurrence may be dropped, got {findings:?}"
        );
    }

    /// A class whose methods' cyclomatic complexities sum past the default
    /// `smells:ck-oo-metrics` WMC threshold (25) — 15 methods at complexity 2
    /// each (a single `if`) sum to 30.
    fn high_wmc_class(name: &str) -> String {
        let methods: String = (0..15)
            .map(|i| format!("    m{i}(a) {{ if (a) {{ return 1; }} return 0; }}\n"))
            .collect();
        format!("class {name} {{\n{methods}}}\n")
    }

    #[tokio::test]
    async fn a_preexisting_whole_file_metric_finding_does_not_block_an_unrelated_edit() {
        let dir =
            std::env::temp_dir().join(format!("vord-hook-wmc-preexisting-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let file = dir.join("big.ts");
        let old_content = high_wmc_class("Big");
        std::fs::write(&file, &old_content).expect("write");

        let policy = AgentPolicy::parse("[agent]\nblocking_rules = [\"smells:ck-oo-metrics\"]\n")
            .expect("parses");

        // Append an unrelated top-level declaration; `Big`'s own methods,
        // and therefore its WMC, are untouched.
        let new_content = format!("{old_content}\nconst unrelated = 1;\n");
        let verdict = judge(&policy, &dir, &file, Some(&new_content))
            .await
            .expect("judged");
        assert!(
            !matches!(verdict, Verdict::Deny { .. }),
            "an unrelated edit to a file that already violated WMC must not be denied, got {verdict:?}"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn a_newly_introduced_whole_file_metric_finding_still_blocks() {
        let dir = std::env::temp_dir().join(format!("vord-hook-wmc-new-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let file = dir.join("big.ts");
        // Clean before this write: a single trivial method, WMC = 1.
        std::fs::write(&file, "class Big {\n    m0() { return 0; }\n}\n").expect("write");

        let policy = AgentPolicy::parse("[agent]\nblocking_rules = [\"smells:ck-oo-metrics\"]\n")
            .expect("parses");

        let new_content = high_wmc_class("Big");
        let verdict = judge(&policy, &dir, &file, Some(&new_content))
            .await
            .expect("judged");
        assert!(
            matches!(verdict, Verdict::Deny { .. }),
            "a write that newly crosses the WMC threshold must still be denied, got {verdict:?}"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    /// A JS/TS function whose cyclomatic complexity (11) exceeds the default
    /// `smells:high-complexity` threshold (10) — ten `if`s plus the implicit
    /// entry path.
    fn high_complexity_function(name: &str) -> String {
        let ifs: String = (0..10)
            .map(|i| format!("    if (a > {i}) {{ return {i}; }}\n"))
            .collect();
        format!("function {name}(a) {{\n{ifs}    return -1;\n}}\n")
    }

    #[tokio::test]
    async fn a_preexisting_complexity_finding_does_not_block_a_pure_comment_addition() {
        // Reproduces the reported bug end to end: a comment-only edit above
        // an untouched, already-too-complex function must not be denied over
        // that function's pre-existing finding, even though inserting the
        // comment shifts the function (and its finding's line) down.
        let dir = std::env::temp_dir().join(format!(
            "vord-hook-complexity-preexisting-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let file = dir.join("busy.ts");
        let old_content = high_complexity_function("busy");
        std::fs::write(&file, &old_content).expect("write");

        let policy = AgentPolicy::parse("[agent]\nblocking_rules = [\"smells:high-complexity\"]\n")
            .expect("parses");

        // A pure comment addition at the top of the file — no function body
        // is touched, but every line below it, including `busy`'s, shifts
        // down by one.
        let new_content = format!("// explains the module\n{old_content}");
        let verdict = judge(&policy, &dir, &file, Some(&new_content))
            .await
            .expect("judged");
        assert!(
            !matches!(verdict, Verdict::Deny { .. }),
            "a pure comment addition must not be denied over an unrelated pre-existing complexity finding, got {verdict:?}"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn a_newly_introduced_complexity_finding_still_blocks() {
        let dir =
            std::env::temp_dir().join(format!("vord-hook-complexity-new-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let file = dir.join("busy.ts");
        // Clean before this write: no branches at all.
        std::fs::write(&file, "function busy(a) {\n    return -1;\n}\n").expect("write");

        let policy = AgentPolicy::parse("[agent]\nblocking_rules = [\"smells:high-complexity\"]\n")
            .expect("parses");

        let new_content = high_complexity_function("busy");
        let verdict = judge(&policy, &dir, &file, Some(&new_content))
            .await
            .expect("judged");
        assert!(
            matches!(verdict, Verdict::Deny { .. }),
            "a write that newly introduces a high-complexity function must still be denied, got {verdict:?}"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn a_required_path_with_no_covering_feature_file_denies_end_to_end() {
        let dir =
            std::env::temp_dir().join(format!("vord-hook-gherkin-missing-{}", std::process::id()));
        std::fs::create_dir_all(dir.join("core/domain")).expect("temp dir");
        let file = dir.join("core/domain/order.rs");

        let policy = AgentPolicy::parse(
            "[[gherkin_required]]\npattern = \"core/domain/**\"\nreason = \"needs a scenario\"\n",
        )
        .expect("parses");
        let verdict = judge(&policy, &dir, &file, Some("struct Order;\n"))
            .await
            .expect("judged");
        let Verdict::Deny { evaluation, .. } = &verdict else {
            panic!("expected a denial, got {verdict:?}")
        };
        assert!(
            evaluation
                .violations
                .iter()
                .any(|v| matches!(v.cause, Cause::MissingGherkinEvidence { .. })),
            "{evaluation:?}"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn a_required_path_with_a_covering_feature_file_is_not_denied_on_that_ground() {
        let dir =
            std::env::temp_dir().join(format!("vord-hook-gherkin-covered-{}", std::process::id()));
        std::fs::create_dir_all(dir.join("core/domain")).expect("temp dir");
        std::fs::create_dir_all(dir.join("features")).expect("features dir");
        std::fs::write(
            dir.join("features/orders.feature"),
            "@covers(core/domain/**)\nFeature: Orders\n  Scenario: Place an order\n    Given a cart\n    When I check out\n    Then the order is placed\n",
        )
        .expect("write feature file");
        let file = dir.join("core/domain/order.rs");

        let policy = AgentPolicy::parse(
            "[[gherkin_required]]\npattern = \"core/domain/**\"\nreason = \"needs a scenario\"\n",
        )
        .expect("parses");
        let verdict = judge(&policy, &dir, &file, Some("struct Order;\n"))
            .await
            .expect("judged");
        if let Verdict::Deny { evaluation, .. } = &verdict {
            assert!(
                !evaluation
                    .violations
                    .iter()
                    .any(|v| matches!(v.cause, Cause::MissingGherkinEvidence { .. })),
                "{evaluation:?}"
            );
        }

        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn a_feature_file_with_a_tag_but_no_scenario_does_not_lift_the_evidence_gate() {
        // The one-line bypass: the cheapest way past `[[gherkin_required]]`
        // is a tag over an empty feature file. If that worked, the gate
        // would be advisory in practice.
        let dir =
            std::env::temp_dir().join(format!("vord-hook-gherkin-stub-{}", std::process::id()));
        std::fs::create_dir_all(dir.join("core/domain")).expect("temp dir");
        std::fs::create_dir_all(dir.join("features")).expect("features dir");
        std::fs::write(
            dir.join("features/orders.feature"),
            "@covers(core/domain/**)\nFeature: Orders\n",
        )
        .expect("write feature file");
        let file = dir.join("core/domain/order.rs");

        let policy = AgentPolicy::parse(
            "[[gherkin_required]]\npattern = \"core/domain/**\"\nreason = \"needs a scenario\"\n",
        )
        .expect("parses");
        let verdict = judge(&policy, &dir, &file, Some("struct Order;\n"))
            .await
            .expect("judged");
        let Verdict::Deny { evaluation, .. } = &verdict else {
            panic!("expected a denial, got {verdict:?}")
        };
        assert!(
            evaluation
                .violations
                .iter()
                .any(|v| matches!(v.cause, Cause::MissingGherkinEvidence { .. })),
            "{evaluation:?}"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn escalation_token_is_none_without_any_escalating_violation() {
        assert!(escalation_token("a.py", &eval_usage_evaluation()).is_none());
    }

    #[test]
    fn escalation_token_is_stable_for_the_same_write_and_differs_for_a_different_one() {
        let policy = AgentPolicy::parse("[agent]\nescalate_rules = [\"smells:long-method\"]\n")
            .expect("parses");
        let evaluation = policy.evaluate("a.py", &[finding_of("smells:long-method", 7)]);
        let token_a = escalation_token("a.py", &evaluation).expect("token");
        let token_b = escalation_token("a.py", &evaluation).expect("token");
        assert_eq!(
            token_a, token_b,
            "the same evaluation must always yield the same token"
        );

        let other_line = policy.evaluate("a.py", &[finding_of("smells:long-method", 9)]);
        let token_c = escalation_token("a.py", &other_line).expect("token");
        assert_ne!(
            token_a, token_c,
            "a materially different finding must yield a different token"
        );
    }

    fn finding_of(rule_id: &str, line: u32) -> Finding {
        Finding {
            rule: RuleId::new(rule_id).expect("rule"),
            severity: vord_rules_engine::Severity::Minor,
            message: "long method".to_string(),
            line,
        }
    }

    #[tokio::test]
    async fn an_unapproved_escalation_blocks_the_write_end_to_end() {
        let dir = std::env::temp_dir().join(format!("vord-hook-escalate-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");

        let policy = AgentPolicy::parse(
            "[agent]\nblocking_rules = []\nescalate_rules = [\"python:subprocess-shell-true\"]\n",
        )
        .expect("parses");
        let file = dir.join("a.py");
        let content = "import subprocess\nsubprocess.run(cmd, shell=True)\n";
        let verdict = judge(&policy, &dir, &file, Some(content))
            .await
            .expect("judged");
        match &verdict {
            Verdict::Deny { evaluation, .. } => {
                assert_eq!(evaluation.escalations().count(), 1);
            }
            other => panic!("expected an unapproved escalation to deny, got {other:?}"),
        }

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn an_approved_token_is_consumed_exactly_once() {
        let dir = std::env::temp_dir().join(format!("vord-hook-approve-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");

        approve_escalation(&dir, "deadbeef").expect("approve");
        let mut approvals = load_approvals(&dir);
        assert!(approvals.contains("deadbeef"));
        assert!(
            approvals.remove("deadbeef"),
            "consuming the token must find it exactly once"
        );
        save_approvals(&dir, &approvals);
        assert!(
            !load_approvals(&dir).contains("deadbeef"),
            "a consumed token must not remain approved"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn an_approved_escalation_lets_the_identical_write_through_end_to_end() {
        let dir =
            std::env::temp_dir().join(format!("vord-hook-approve-flow-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");

        let policy = AgentPolicy::parse(
            "[agent]\nblocking_rules = []\nescalate_rules = [\"python:subprocess-shell-true\"]\n",
        )
        .expect("parses");
        let file = dir.join("a.py");
        let content = "import subprocess\nsubprocess.run(cmd, shell=True)\n";

        let first = judge(&policy, &dir, &file, Some(content))
            .await
            .expect("judged");
        let Verdict::Deny { path, evaluation } = &first else {
            panic!("expected a first-attempt denial")
        };
        let token = escalation_token(path, evaluation).expect("token");
        approve_escalation(&dir, &token).expect("approve");

        // A byte-identical retry now reproduces the identical finding, so
        // `judge` re-derives the identical token, finds it approved, and
        // consumes it — letting the write through as if it were clean.
        let second = judge(&policy, &dir, &file, Some(content))
            .await
            .expect("judged");
        assert!(
            matches!(second, Verdict::Silent),
            "an approved escalation must let the retry through, got {second:?}"
        );

        // Approval is single-use: a third identical attempt must escalate again.
        let third = judge(&policy, &dir, &file, Some(content))
            .await
            .expect("judged");
        assert!(
            matches!(third, Verdict::Deny { .. }),
            "a consumed token must not approve a later retry, got {third:?}"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn append_and_read_audit_log_round_trips_a_denial() {
        let dir = std::env::temp_dir().join(format!("vord-hook-audit-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");

        let verdict = Verdict::from_evaluation("a.py".to_string(), eval_usage_evaluation());
        append_audit_log(
            &dir,
            "PreToolUse",
            &verdict,
            &CircuitBreakerReport::default(),
            &LoopGuardReport::default(),
        );

        let entries = read_audit_log(&dir, None);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0]["path"], "a.py");
        assert_eq!(entries[0]["outcome"], "deny");
        assert_eq!(entries[0]["event"], "PreToolUse");
        assert_eq!(entries[0]["violations"][0]["rule"], "owasp:eval-usage");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_silent_verdict_is_never_written_to_the_audit_log() {
        let dir =
            std::env::temp_dir().join(format!("vord-hook-audit-silent-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");

        append_audit_log(
            &dir,
            "PreToolUse",
            &Verdict::Silent,
            &CircuitBreakerReport::default(),
            &LoopGuardReport::default(),
        );
        assert!(
            read_audit_log(&dir, None).is_empty(),
            "a clean write must leave no audit trail"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn read_audit_log_limit_keeps_only_the_most_recent_entries() {
        let dir =
            std::env::temp_dir().join(format!("vord-hook-audit-limit-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");

        for line in 1..=5 {
            let evaluation = AgentPolicy::default().evaluate(
                "a.py",
                &[Finding {
                    rule: RuleId::new("owasp:eval-usage").expect("rule"),
                    severity: vord_rules_engine::Severity::Blocker,
                    message: format!("attempt {line}"),
                    line,
                }],
            );
            let verdict = Verdict::from_evaluation("a.py".to_string(), evaluation);
            append_audit_log(
                &dir,
                "check",
                &verdict,
                &CircuitBreakerReport::default(),
                &LoopGuardReport::default(),
            );
        }

        let entries = read_audit_log(&dir, Some(2));
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0]["violations"][0]["message"], "attempt 4");
        assert_eq!(entries[1]["violations"][0]["message"], "attempt 5");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn render_audit_text_reports_when_the_log_is_empty() {
        let text = render_audit_text(&[]);
        assert!(text.contains("no audit log entries"), "{text}");
    }
}
