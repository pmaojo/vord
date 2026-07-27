//! Agentic guardrail: yunq inside an autonomous agent's edit loop.
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
//! callers (CI, `pre-commit`) can tell exit 1 (yunq broke) from exit 2
//! (policy denied) and decide for themselves.

use std::io::Read;
use std::path::{Path, PathBuf};

use yunq_agent_policy::{AgentPolicy, Cause, CircuitBreakerState, Enforcement, Evaluation, Finding, Violation};
use yunq_infra_memory::{InMemoryIssueStorage, InMemoryMetricsTracker};
use yunq_rules_engine::RuleId;

/// Filename of the Agent Permission Policy, read from the repository root.
pub const POLICY_FILE: &str = "yunq-policy.toml";

/// Filename of the circuit breaker's persisted per-rule failure counts, read from and written to
/// the repository root alongside the policy.
pub const CIRCUIT_BREAKER_FILE: &str = ".yunq-circuit-breaker.json";

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
    Deny { path: String, evaluation: Evaluation },
    /// Findings worth reporting that do not deny.
    Advise { path: String, evaluation: Evaluation },
}

impl Verdict {
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
    let Ok(raw) = std::fs::read_to_string(&path) else { return CircuitBreakerState::default() };
    let Ok(counts) = serde_json::from_str::<Vec<CircuitBreakerEntry>>(&raw) else {
        return CircuitBreakerState::default();
    };
    CircuitBreakerState::from_counts(
        counts.into_iter().filter_map(|entry| RuleId::new(&entry.rule).ok().map(|rule| (rule, entry.count))),
    )
}

/// Persists the circuit breaker's state. Best-effort: a write failure is reported on stderr rather
/// than surfaced as a denial — losing this state merely forgets a streak on the next write, an
/// availability concern for a soft feature, not a security one.
pub fn save_circuit_breaker(root: &Path, state: &CircuitBreakerState) {
    let entries: Vec<CircuitBreakerEntry> =
        state.counts().map(|(rule, count)| CircuitBreakerEntry { rule: rule.to_string(), count }).collect();
    let path = root.join(CIRCUIT_BREAKER_FILE);
    match serde_json::to_string_pretty(&entries) {
        Ok(raw) => {
            if let Err(e) = std::fs::write(&path, raw) {
                eprintln!("yunq hook: could not persist circuit breaker state at {}: {e}", path.display());
            }
        }
        Err(e) => eprintln!("yunq hook: could not serialize circuit breaker state: {e}"),
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

/// The structured, machine-readable counterpart to [`denial_text`] / [`advisory_text`]: every
/// violation as a JSON object naming the exact rule, line and the deterministic condition that
/// must hold for it to clear, rather than prose a caller has to pattern-match. This is the
/// contract `hook check --format json` speaks on stdout, and it is also embedded (as a fenced
/// block) inside the prose the Claude Code hook returns, so an agent that wants exact parsing does
/// not have to choose between the two.
pub fn structured_report(path: &str, evaluation: &Evaluation, breaker: &CircuitBreakerReport) -> serde_json::Value {
    serde_json::json!({
        "path": path,
        "denied": evaluation.is_denied(),
        "circuit_breaker_tripped": breaker.is_tripped(),
        "violations": evaluation.violations.iter().map(|v| violation_json(v, breaker)).collect::<Vec<_>>(),
    })
}

fn violation_json(violation: &Violation, breaker: &CircuitBreakerReport) -> serde_json::Value {
    let (rule, severity, line, message) = match &violation.finding {
        Some(f) => (Some(f.rule.to_string()), Some(f.severity.to_string()), Some(f.line), Some(f.message.clone())),
        None => (None, None, None, None),
    };
    let (cause, expected_state) = match &violation.cause {
        Cause::ProtectedPath { pattern, reason } => {
            ("protected_path", format!("path must not match `{pattern}` ({reason})"))
        }
        Cause::BlockingRule => (
            "blocking_rule",
            match &rule {
                Some(r) => format!("no finding for rule `{r}` in this write"),
                None => "no blocking finding in this write".to_string(),
            },
        ),
        Cause::SeverityThreshold { threshold } => {
            ("severity_threshold", format!("no finding at or above severity `{threshold}` in this write"))
        }
    };
    let circuit_breaker_tripped = rule.as_deref().is_some_and(|r| breaker.tripped.iter().any(|t| t.as_str() == r));
    serde_json::json!({
        "rule": rule,
        "severity": severity,
        "line": line,
        "message": message,
        "enforcement": match violation.enforcement { Enforcement::Deny => "deny", Enforcement::Warn => "warn" },
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
pub fn proposed_content(tool_name: &str, tool_input: &serde_json::Value, file: &Path) -> Option<String> {
    let field = |key: &str| tool_input.get(key).and_then(|v| v.as_str());
    match tool_name {
        "Write" => field("content").map(|s| s.to_string()),
        "Edit" => {
            let old = field("old_string")?;
            let new = field("new_string")?;
            let current = std::fs::read_to_string(file).ok()?;
            let replace_all = tool_input.get("replace_all").and_then(|v| v.as_bool()).unwrap_or(false);
            Some(if replace_all { current.replace(old, new) } else { current.replacen(old, new, 1) })
        }
        _ => None,
    }
}

/// Runs the full analyzer over a single in-memory file and maps its issues
/// into policy findings.
///
/// `relative` must be repository-relative: `SourceFile` rejects absolute
/// paths, and the policy's path globs are written against repository-relative
/// paths too.
///
/// Returns an empty vector for a file whose extension maps to no language —
/// there is nothing to parse, which is not an error, and the path half of
/// the policy still gets its say.
pub async fn analyze_content(relative: &str, content: &str) -> anyhow::Result<Vec<Finding>> {
    let extension = Path::new(relative).extension().and_then(|e| e.to_str()).unwrap_or("");
    let Some(language) = yunq_ast::LanguageIdentifier::from_extension(extension) else {
        return Ok(Vec::new());
    };
    let source = yunq_ast::SourceFile::new(relative.to_string(), content.to_string(), language)
        .map_err(|e| anyhow::anyhow!("invalid source path {relative:?}: {e}"))?;

    let service = crate::default_service(InMemoryIssueStorage::new(), InMemoryMetricsTracker::new());
    let report = service.analyze_files(std::slice::from_ref(&source)).await?;

    Ok(report
        .issues()
        .iter()
        .map(|issue| Finding {
            rule: issue.rule().clone(),
            severity: issue.severity(),
            message: issue.message().to_string(),
            line: issue.span().start_line,
        })
        .collect())
}

/// Judges one proposed write end to end: policy, path, and (when content is
/// available and parseable) findings.
pub async fn judge(
    policy: &AgentPolicy,
    root: &Path,
    file: &Path,
    content: Option<&str>,
) -> anyhow::Result<Verdict> {
    let relative = relative_to(root, file);
    let findings = match content {
        Some(content) => analyze_content(&relative, content).await?,
        None => Vec::new(),
    };
    let evaluation = policy.evaluate(&relative, &findings);
    Ok(Verdict::from_evaluation(relative, evaluation))
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
pub fn denial_text(path: &str, evaluation: &Evaluation, timing: Timing, breaker: &CircuitBreakerReport) -> String {
    let mut out = match timing {
        Timing::Prevented => format!("yunq blocked this write to `{path}`.\n\n"),
        Timing::AlreadyWritten => {
            format!("yunq policy violation in `{path}` — this file has ALREADY been written to disk.\n\n")
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
            "\nThis is an Agent Permission Policy block from yunq-policy.toml, not a style \
             preference. The file was NOT written. Rewrite the code so these findings do not \
             occur, then write it again. Do not retry the same content, and do not disable \
             the policy.\n"
        }
        Timing::AlreadyWritten => {
            "\nThis is an Agent Permission Policy violation from yunq-policy.toml, not a style \
             preference. The offending content is on disk now — fix it before doing anything \
             else, and do not disable the policy.\n"
        }
    });
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
    out.push_str(&format!(
        "\nMachine-readable form:\n{}\n",
        serde_json::to_string(&structured_report(path, evaluation, breaker)).unwrap_or_default(),
    ));
    out
}

/// The non-blocking counterpart: findings worth putting in front of the model
/// without stopping it.
pub fn advisory_text(path: &str, evaluation: &Evaluation) -> String {
    let mut out = format!("yunq found issues in `{path}`:\n\n");
    for violation in &evaluation.violations {
        out.push_str(&format!("  - {}\n", violation.describe()));
    }
    out.push_str("\nConsider fixing these before moving on.\n");
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
/// auto-approve every edit yunq happens not to object to, turning a security
/// tool into a permission bypass. Staying silent lets the host's normal
/// permission flow run untouched.
pub fn claude_code_output(event: &str, verdict: &Verdict, breaker: &CircuitBreakerReport) -> Option<serde_json::Value> {
    match (event, verdict) {
        (_, Verdict::Silent) => None,
        ("PreToolUse", Verdict::Deny { path, evaluation }) => Some(serde_json::json!({
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": denial_text(path, evaluation, Timing::Prevented, breaker),
            }
        })),
        // Pre-write advisories are deliberately dropped: the only way to
        // attach them here is alongside an `allow`, and see above.
        ("PreToolUse", Verdict::Advise { .. }) => None,
        ("PostToolUse", Verdict::Deny { path, evaluation }) => Some(serde_json::json!({
            "decision": "block",
            "reason": denial_text(path, evaluation, Timing::AlreadyWritten, breaker),
        })),
        ("PostToolUse", Verdict::Advise { path, evaluation }) => Some(serde_json::json!({
            "hookSpecificOutput": {
                "hookEventName": "PostToolUse",
                "additionalContext": advisory_text(path, evaluation),
            }
        })),
        _ => None,
    }
}

/// `yunq hook claude-code`: reads the hook payload on stdin, writes the
/// verdict JSON on stdout, always exits 0.
///
/// Exit 0 with a JSON body is the documented way to deny; exit 2 also denies
/// but forces the reason through stderr, losing the structured form. Using
/// the JSON path uniformly means one code path for both events.
pub async fn run_claude_code() -> anyhow::Result<std::process::ExitCode> {
    let mut raw = String::new();
    std::io::stdin().read_to_string(&mut raw)?;

    let verdict = match claude_code_verdict(&raw).await {
        Ok(verdict) => verdict,
        Err(e) => {
            // Fail open: the agent keeps working, the operator sees why.
            eprintln!("yunq hook: {e:#}");
            return Ok(std::process::ExitCode::SUCCESS);
        }
    };

    let payload: HookPayload = serde_json::from_str(&raw).unwrap_or(HookPayload {
        hook_event_name: String::new(),
        tool_name: String::new(),
        tool_input: serde_json::Value::Null,
        cwd: None,
    });
    let root =
        payload.cwd.as_ref().map(PathBuf::from).or_else(|| std::env::current_dir().ok()).unwrap_or_else(|| PathBuf::from("."));
    let breaker = track_circuit_breaker(&root, &verdict);
    if let Some(output) = claude_code_output(&payload.hook_event_name, &verdict, &breaker) {
        println!("{}", serde_json::to_string(&output)?);
    }
    Ok(std::process::ExitCode::SUCCESS)
}

/// The analysable half of the Claude Code hook, split out so the wiring
/// above stays a thin shell around a function that can be tested.
async fn claude_code_verdict(raw: &str) -> anyhow::Result<Verdict> {
    let payload: HookPayload = serde_json::from_str(raw).map_err(|e| anyhow::anyhow!("bad hook payload: {e}"))?;

    let Some(file_path) = payload.tool_input.get("file_path").and_then(|v| v.as_str()) else {
        return Ok(Verdict::Silent);
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
        return Ok(Verdict::Silent);
    }

    // Pre-write: judge what the agent is about to write. Post-write: it is
    // already on disk, so disk is the truth.
    let content = match payload.hook_event_name.as_str() {
        "PreToolUse" => proposed_content(&payload.tool_name, &payload.tool_input, &file),
        _ => std::fs::read_to_string(&file).ok(),
    };

    judge(&policy, &root, &file, content.as_deref()).await
}

// ---------------------------------------------------------------------------
// Portable adapter
// ---------------------------------------------------------------------------

/// `yunq hook check <file>`: the host-agnostic gate.
///
/// Exit codes are the contract here, since there is no host to speak JSON to:
/// `0` allowed, `2` denied by policy, `1` yunq itself failed. Callers that
/// must not be blocked by a yunq bug can treat 1 as success; callers that
/// want strictness can treat it as failure. Both are possible only because
/// the two are distinguishable.
pub async fn run_check(file: PathBuf, format: HookOutputFormat) -> anyhow::Result<std::process::ExitCode> {
    let root = std::env::current_dir()?;
    let policy = load_policy(&root)?;
    if !policy.enabled() {
        return Ok(std::process::ExitCode::SUCCESS);
    }

    let content = std::fs::read_to_string(&file).ok();
    let verdict = judge(&policy, &root, &file, content.as_deref()).await?;
    let breaker = track_circuit_breaker(&root, &verdict);

    match verdict {
        Verdict::Silent => Ok(std::process::ExitCode::SUCCESS),
        Verdict::Advise { path, evaluation } => {
            match format {
                HookOutputFormat::Json => {
                    println!("{}", serde_json::to_string_pretty(&structured_report(&path, &evaluation, &breaker))?)
                }
                HookOutputFormat::Text => eprintln!("{}", advisory_text(&path, &evaluation)),
            }
            Ok(std::process::ExitCode::SUCCESS)
        }
        Verdict::Deny { path, evaluation } => {
            // `check` judges a file that exists, so the write has landed by
            // definition — even when the caller is a pre-commit hook about
            // to reject the commit that carries it.
            match format {
                HookOutputFormat::Json => {
                    println!("{}", serde_json::to_string_pretty(&structured_report(&path, &evaluation, &breaker))?)
                }
                HookOutputFormat::Text => {
                    eprintln!("{}", denial_text(&path, &evaluation, Timing::AlreadyWritten, &breaker))
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
        assert_eq!(proposed_content("Write", &input, Path::new("/nonexistent")).as_deref(), Some("const a = 1;"));
    }

    #[test]
    fn an_edit_tool_call_is_applied_to_the_file_on_disk() {
        let dir = std::env::temp_dir().join(format!("yunq-hook-edit-{}", std::process::id()));
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
        assert_eq!(proposed_content("Edit", &all, &file).as_deref(), Some("const a = 2;\nconst b = 2;\n"));

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn an_unrecognized_tool_yields_no_content_rather_than_a_guess() {
        let input = serde_json::json!({ "file_path": "/tmp/a.ipynb", "new_source": "x = 1" });
        assert!(proposed_content("NotebookEdit", &input, Path::new("/tmp/a.ipynb")).is_none());
    }

    #[test]
    fn an_absolute_tool_path_is_rebased_onto_the_repository_root() {
        assert_eq!(relative_to(Path::new("/repo"), Path::new("/repo/src/a.ts")), "src/a.ts");
    }

    #[test]
    fn a_path_outside_the_root_still_produces_a_relative_form() {
        // `SourceFile` rejects absolute paths outright, so leaking one here
        // would turn an out-of-tree edit into a hard error instead of a
        // judgement.
        assert_eq!(relative_to(Path::new("/repo"), Path::new("/etc/passwd")), "etc/passwd");
    }

    #[tokio::test]
    async fn a_file_with_no_known_extension_analyses_to_no_findings() {
        assert!(analyze_content("notes.unknownext", "whatever").await.expect("ok").is_empty());
    }

    #[tokio::test]
    async fn a_real_vulnerability_in_proposed_content_is_found() {
        let findings = analyze_content("app.py", "import subprocess\nsubprocess.run(cmd, shell=True)\n")
            .await
            .expect("analysis runs");
        assert!(
            findings.iter().any(|f| f.rule.as_str() == "python:subprocess-shell-true"),
            "expected shell=True to be found, got {findings:?}"
        );
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
        let verdict = judge(&policy, Path::new("/repo"), Path::new("/repo/a.py"), Some("x = 1\n"))
            .await
            .expect("judged");
        assert!(matches!(verdict, Verdict::Silent), "got {verdict:?}");
    }

    #[test]
    fn pre_tool_use_emits_a_deny_decision() {
        let evaluation = AgentPolicy::default().evaluate(
            "a.py",
            &[Finding {
                rule: yunq_rules_engine::RuleId::new("owasp:eval-usage").expect("rule"),
                severity: yunq_rules_engine::Severity::Blocker,
                message: "eval".to_string(),
                line: 3,
            }],
        );
        let verdict = Verdict::from_evaluation("a.py".to_string(), evaluation);
        let output = claude_code_output("PreToolUse", &verdict, &CircuitBreakerReport::default()).expect("emits");
        assert_eq!(output["hookSpecificOutput"]["permissionDecision"], "deny");
        let reason = output["hookSpecificOutput"]["permissionDecisionReason"].as_str().expect("reason");
        assert!(reason.contains("owasp:eval-usage"), "{reason}");
        assert!(reason.contains("line 3"), "{reason}");
    }

    #[test]
    fn post_tool_use_blocks_with_a_reason_instead_of_a_permission_decision() {
        let evaluation = AgentPolicy::default().evaluate(
            "a.py",
            &[Finding {
                rule: yunq_rules_engine::RuleId::new("owasp:eval-usage").expect("rule"),
                severity: yunq_rules_engine::Severity::Blocker,
                message: "eval".to_string(),
                line: 3,
            }],
        );
        let verdict = Verdict::from_evaluation("a.py".to_string(), evaluation);
        let output = claude_code_output("PostToolUse", &verdict, &CircuitBreakerReport::default()).expect("emits");
        assert_eq!(output["decision"], "block");
        assert!(output["reason"].as_str().expect("reason").contains("owasp:eval-usage"));
    }

    #[test]
    fn the_two_events_disagree_about_whether_the_file_was_written() {
        // The model acts on this sentence. Telling it "blocked, not written"
        // after a PostToolUse — where the bytes are already on disk — makes
        // it move on and leave the finding in the tree.
        let evaluation = AgentPolicy::default().evaluate(
            "a.py",
            &[Finding {
                rule: yunq_rules_engine::RuleId::new("owasp:eval-usage").expect("rule"),
                severity: yunq_rules_engine::Severity::Blocker,
                message: "eval".to_string(),
                line: 3,
            }],
        );

        let breaker = CircuitBreakerReport::default();
        let prevented = denial_text("a.py", &evaluation, Timing::Prevented, &breaker);
        assert!(prevented.contains("was NOT written"), "{prevented}");

        let landed = denial_text("a.py", &evaluation, Timing::AlreadyWritten, &breaker);
        assert!(landed.contains("ALREADY been written"), "{landed}");
        assert!(!landed.contains("was NOT written"), "{landed}");
    }

    #[test]
    fn a_silent_verdict_emits_nothing_on_either_event() {
        let breaker = CircuitBreakerReport::default();
        assert!(claude_code_output("PreToolUse", &Verdict::Silent, &breaker).is_none());
        assert!(claude_code_output("PostToolUse", &Verdict::Silent, &breaker).is_none());
    }

    #[test]
    fn pre_tool_use_never_emits_allow_for_an_advisory() {
        // Regression guard for a permission bypass: emitting `allow` here
        // would auto-approve every edit yunq does not object to.
        let evaluation = AgentPolicy::parse("[agent]\nadvisory_rules = [\"owasp:eval-usage\"]\n")
            .expect("parses")
            .evaluate(
                "a.py",
                &[Finding {
                    rule: yunq_rules_engine::RuleId::new("owasp:eval-usage").expect("rule"),
                    severity: yunq_rules_engine::Severity::Blocker,
                    message: "eval".to_string(),
                    line: 3,
                }],
            );
        let verdict = Verdict::from_evaluation("a.py".to_string(), evaluation);
        assert!(matches!(verdict, Verdict::Advise { .. }));
        assert!(claude_code_output("PreToolUse", &verdict, &CircuitBreakerReport::default()).is_none());
    }

    #[tokio::test]
    async fn a_malformed_payload_is_an_error_that_the_caller_fails_open_on() {
        assert!(claude_code_verdict("not json at all").await.is_err());
    }

    #[tokio::test]
    async fn a_payload_with_no_file_path_is_silent() {
        let raw = r#"{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"ls"}}"#;
        assert!(matches!(claude_code_verdict(raw).await.expect("ok"), Verdict::Silent));
    }

    fn eval_usage_evaluation() -> Evaluation {
        AgentPolicy::default().evaluate(
            "a.py",
            &[Finding {
                rule: RuleId::new("owasp:eval-usage").expect("rule"),
                severity: yunq_rules_engine::Severity::Blocker,
                message: "eval".to_string(),
                line: 3,
            }],
        )
    }

    #[test]
    fn structured_report_names_the_rule_line_and_expected_state() {
        let evaluation = eval_usage_evaluation();
        let report = structured_report("a.py", &evaluation, &CircuitBreakerReport::default());
        assert_eq!(report["path"], "a.py");
        assert_eq!(report["denied"], true);
        assert_eq!(report["circuit_breaker_tripped"], false);
        let violation = &report["violations"][0];
        assert_eq!(violation["rule"], "owasp:eval-usage");
        assert_eq!(violation["line"], 3);
        assert_eq!(violation["enforcement"], "deny");
        assert_eq!(violation["cause"], "blocking_rule");
        assert!(violation["expected_state"].as_str().expect("state").contains("owasp:eval-usage"));
    }

    #[test]
    fn a_protected_path_violation_has_no_rule_in_the_structured_report() {
        let policy =
            AgentPolicy::parse("[[protected_path]]\npattern = \".github/workflows/**\"\nreason = \"CI.\"\n")
                .expect("parses");
        let evaluation = policy.evaluate(".github/workflows/ci.yml", &[]);
        let report = structured_report(".github/workflows/ci.yml", &evaluation, &CircuitBreakerReport::default());
        let violation = &report["violations"][0];
        assert_eq!(violation["rule"], serde_json::Value::Null);
        assert_eq!(violation["cause"], "protected_path");
    }

    #[test]
    fn denial_text_embeds_a_parseable_machine_readable_block() {
        let evaluation = eval_usage_evaluation();
        let text = denial_text("a.py", &evaluation, Timing::Prevented, &CircuitBreakerReport::default());
        let json_line = text.lines().last().expect("a line");
        let parsed: serde_json::Value = serde_json::from_str(json_line).expect("valid json");
        assert_eq!(parsed["violations"][0]["rule"], "owasp:eval-usage");
    }

    #[test]
    fn a_tripped_breaker_adds_a_stop_and_rollback_instruction() {
        let evaluation = eval_usage_evaluation();
        let breaker = CircuitBreakerReport { tripped: vec![RuleId::new("owasp:eval-usage").expect("rule")] };
        let text = denial_text("a.py", &evaluation, Timing::Prevented, &breaker);
        assert!(text.contains("CIRCUIT BREAKER TRIPPED"), "{text}");
        assert!(text.contains("Revert"), "{text}");
        assert!(text.to_lowercase().contains("human"), "{text}");
    }

    #[test]
    fn a_verdict_without_a_tripped_rule_adds_no_stop_instruction() {
        let evaluation = eval_usage_evaluation();
        let text = denial_text("a.py", &evaluation, Timing::Prevented, &CircuitBreakerReport::default());
        assert!(!text.contains("CIRCUIT BREAKER"), "{text}");
    }

    #[test]
    fn the_circuit_breaker_state_persists_across_separate_invocations() {
        let dir = std::env::temp_dir().join(format!("yunq-hook-breaker-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");

        let verdict = Verdict::from_evaluation("a.py".to_string(), eval_usage_evaluation());

        assert!(!track_circuit_breaker(&dir, &verdict).is_tripped());
        assert!(!track_circuit_breaker(&dir, &verdict).is_tripped());
        let third = track_circuit_breaker(&dir, &verdict);
        assert!(third.is_tripped(), "the third consecutive denial of the same rule must trip");
        assert_eq!(third.tripped, vec![RuleId::new("owasp:eval-usage").expect("rule")]);

        reset_circuit_breaker(&dir).expect("reset");
        assert!(!track_circuit_breaker(&dir, &verdict).is_tripped(), "reset clears the persisted streak");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_clean_write_resets_the_persisted_streak() {
        let dir = std::env::temp_dir().join(format!("yunq-hook-breaker-reset-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");

        let denied = Verdict::from_evaluation("a.py".to_string(), eval_usage_evaluation());
        track_circuit_breaker(&dir, &denied);
        track_circuit_breaker(&dir, &denied);

        track_circuit_breaker(&dir, &Verdict::Silent);
        let third = track_circuit_breaker(&dir, &denied);
        assert!(!third.is_tripped(), "the silent write in between broke the streak");

        std::fs::remove_dir_all(&dir).ok();
    }
}
