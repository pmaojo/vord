//! `yunq hook install` — wires the guardrail into a repository.
//!
//! Two artifacts, both committed to the repository rather than kept in a
//! developer's home directory: `.claude/settings.json` (so every agent run
//! in this repository is gated, on every teammate's machine and in CI) and
//! `yunq-policy.toml` (so the rules the agent is held to are reviewable in
//! the same pull request as the code they govern).
//!
//! The settings merge is the delicate part. `.claude/settings.json` is a
//! file the user owns and may have arbitrary unrelated content in, so the
//! merge is additive and idempotent: unknown keys are preserved untouched,
//! and re-running install never duplicates the hook.

use std::path::Path;

use serde_json::{json, Map, Value};

/// The command the hooks invoke. Deliberately a bare `yunq` rather than an
/// absolute path: this file gets committed and shared, and an absolute path
/// from the installing developer's machine is wrong on everyone else's.
pub const DEFAULT_HOOK_COMMAND: &str = "yunq hook claude-code";

/// The policy shipped on install.
///
/// Unlike [`yunq_agent_policy::AgentPolicy::default`] — which has no
/// protected paths, because an invisible default that silently refuses
/// edits is hostile — this template turns path protection *on* with concrete
/// entries. The difference is visibility: this text lands in the user's own
/// repository where they can read, edit or delete it in the same commit that
/// installed it.
pub const POLICY_TEMPLATE: &str = r#"# yunq Agent Permission Policy
#
# Governs what an autonomous coding agent (Claude Code, and any host wired to
# `yunq hook check`) is allowed to write. This is not the quality gate: the
# gate asks "is this project releasable?", this asks "may this one write
# land?" — and answers before the bytes reach disk.
#
# Verify any change here with:  yunq hook check <file>

[agent]
enabled = true

# Deny a write introducing a finding at or above this severity.
# info | minor | major | critical | blocker
block_at_or_above = "critical"

# Rules an agent may never introduce, whatever severity the quality profile
# gives them. This is the list that makes an agent policy different from a
# severity threshold: an agent writing a shell sink is categorically riskier
# than a human doing it under review, even when the rule scores as a warning.
blocking_rules = [
  "ai:llm-output-injection",
  "owasp:command-execution",
  "owasp:eval-usage",
  "python:subprocess-shell-true",
  "php:eval-usage",
  "php:command-execution",
]

# Rules that report but never deny. The escape hatch for a rule that is noisy
# in this repository — outranks both the blocking list and the threshold.
# Also where to opt into rules that are not AST findings, e.g.
# "supply-chain:new-dependency" (flags a package.json/requirements.txt
# dependency an agent's write adds that was not there before — never denies
# by default, since most new dependencies are legitimate).
advisory_rules = []

# Rules that block like `blocking_rules`, but a human can lift the block for
# one specific write with `yunq hook approve <token>` (the token is printed
# in the denial). Use this for findings that are too risky to let an agent
# resolve unsupervised but are not always wrong — a blanket block would just
# get the policy edited to remove the rule.
escalate_rules = []

# Stricter threshold for a path yunq has already seen an agent write to (or
# attempt to write to) before — tracked automatically in
# .yunq-provenance.json, no manual "mark this file as AI-generated" step
# required. Only the threshold tightens here; blocking_rules/escalate_rules/
# advisory_rules above apply the same regardless of a path's provenance.
[agent.ai_touched]
block_at_or_above = "major"

# Paths an agent may not touch at all, with no finding required. Delete any
# entry that does not fit how this repository works; an agent that cannot do
# its job will be given a wider blast radius by whoever is annoyed enough.
[[protected_path]]
pattern = ".github/workflows/**"
reason = "CI definitions gate every other control; changes need human review."

[[protected_path]]
pattern = "**/*.tf"
reason = "Terraform changes can rewrite IAM and networking; human review required."
"#;

/// Merges yunq's hooks into an existing `.claude/settings.json` value.
///
/// Pure so the merge can be tested against real-world settings shapes
/// without touching a filesystem. Returns the updated value and whether
/// anything actually changed, so the caller can report "already installed"
/// instead of rewriting an identical file.
pub fn merge_hooks(mut settings: Value, command: &str) -> (Value, bool) {
    if !settings.is_object() {
        settings = Value::Object(Map::new());
    }
    let root = settings.as_object_mut().expect("just ensured object");
    let hooks = root.entry("hooks").or_insert_with(|| Value::Object(Map::new()));
    if !hooks.is_object() {
        *hooks = Value::Object(Map::new());
    }
    let hooks = hooks.as_object_mut().expect("just ensured object");

    let mut changed = false;
    for event in ["PreToolUse", "PostToolUse"] {
        let entry = hooks.entry(event).or_insert_with(|| Value::Array(Vec::new()));
        if !entry.is_array() {
            *entry = Value::Array(Vec::new());
        }
        let matchers = entry.as_array_mut().expect("just ensured array");

        if already_installed(matchers, command) {
            continue;
        }
        matchers.push(json!({
            "matcher": "Edit|Write",
            "hooks": [{
                "type": "command",
                "command": command,
                // Bounded so a wedged analysis cannot hang the agent
                // indefinitely; a single-file scan is far under this.
                "timeout": 30,
                "statusMessage": "yunq guardrail",
            }],
        }));
        changed = true;
    }

    (settings, changed)
}

/// True when any matcher group already runs `command` — the idempotency
/// check. Matches on the command string rather than the matcher pattern so a
/// user who narrowed the matcher (say, to `Write` only) does not get a
/// second, wider hook silently appended on the next install.
fn already_installed(matchers: &[Value], command: &str) -> bool {
    matchers.iter().any(|group| {
        group
            .get("hooks")
            .and_then(|h| h.as_array())
            .is_some_and(|hooks| hooks.iter().any(|h| h.get("command").and_then(|c| c.as_str()) == Some(command)))
    })
}

/// Writes both artifacts into `root`, reporting what it did.
pub fn install(root: &Path, command: &str) -> anyhow::Result<()> {
    let policy_path = root.join(yunq_cli::hook::POLICY_FILE);
    if policy_path.exists() {
        println!("✅ {} already exists — left untouched", policy_path.display());
    } else {
        std::fs::write(&policy_path, POLICY_TEMPLATE)
            .map_err(|e| anyhow::anyhow!("cannot write {}: {e}", policy_path.display()))?;
        println!("📝 Wrote {}", policy_path.display());
    }

    let settings_dir = root.join(".claude");
    std::fs::create_dir_all(&settings_dir)
        .map_err(|e| anyhow::anyhow!("cannot create {}: {e}", settings_dir.display()))?;
    let settings_path = settings_dir.join("settings.json");

    // A settings file that exists but does not parse is not overwritten:
    // silently replacing a user's configuration because of a stray comma is
    // a far worse outcome than refusing to install.
    let existing = if settings_path.exists() {
        let raw = std::fs::read_to_string(&settings_path)
            .map_err(|e| anyhow::anyhow!("cannot read {}: {e}", settings_path.display()))?;
        if raw.trim().is_empty() {
            Value::Object(Map::new())
        } else {
            serde_json::from_str(&raw)
                .map_err(|e| anyhow::anyhow!("{} is not valid JSON ({e}) — fix or move it, then re-run", settings_path.display()))?
        }
    } else {
        Value::Object(Map::new())
    };

    let (merged, changed) = merge_hooks(existing, command);
    if changed {
        std::fs::write(&settings_path, format!("{}\n", serde_json::to_string_pretty(&merged)?))
            .map_err(|e| anyhow::anyhow!("cannot write {}: {e}", settings_path.display()))?;
        println!("🪝 Installed PreToolUse + PostToolUse hooks in {}", settings_path.display());
    } else {
        println!("✅ Hooks already present in {} — nothing to do", settings_path.display());
    }

    println!(
        "\nThe guardrail is active for agents run in this repository.\n\
         `{command}` must be on PATH. Verify with:  yunq hook check <file>"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn installing_into_empty_settings_adds_both_events() {
        let (merged, changed) = merge_hooks(json!({}), DEFAULT_HOOK_COMMAND);
        assert!(changed);
        assert_eq!(merged["hooks"]["PreToolUse"][0]["matcher"], "Edit|Write");
        assert_eq!(merged["hooks"]["PreToolUse"][0]["hooks"][0]["command"], DEFAULT_HOOK_COMMAND);
        assert_eq!(merged["hooks"]["PostToolUse"][0]["hooks"][0]["command"], DEFAULT_HOOK_COMMAND);
    }

    #[test]
    fn installing_twice_changes_nothing_the_second_time() {
        let (once, _) = merge_hooks(json!({}), DEFAULT_HOOK_COMMAND);
        let (twice, changed) = merge_hooks(once.clone(), DEFAULT_HOOK_COMMAND);
        assert!(!changed, "install must be idempotent");
        assert_eq!(once, twice);
    }

    #[test]
    fn unrelated_settings_survive_the_merge() {
        let existing = json!({
            "model": "opus",
            "permissions": { "allow": ["Bash(git status)"] },
            "hooks": { "Stop": [{ "matcher": "", "hooks": [{ "type": "command", "command": "notify" }] }] }
        });
        let (merged, changed) = merge_hooks(existing, DEFAULT_HOOK_COMMAND);
        assert!(changed);
        assert_eq!(merged["model"], "opus");
        assert_eq!(merged["permissions"]["allow"][0], "Bash(git status)");
        assert_eq!(merged["hooks"]["Stop"][0]["hooks"][0]["command"], "notify", "other events untouched");
        assert_eq!(merged["hooks"]["PreToolUse"][0]["hooks"][0]["command"], DEFAULT_HOOK_COMMAND);
    }

    #[test]
    fn an_existing_hook_on_the_same_event_is_kept_alongside_ours() {
        let existing = json!({
            "hooks": { "PreToolUse": [{ "matcher": "Bash", "hooks": [{ "type": "command", "command": "audit" }] }] }
        });
        let (merged, _) = merge_hooks(existing, DEFAULT_HOOK_COMMAND);
        let pre = merged["hooks"]["PreToolUse"].as_array().expect("array");
        assert_eq!(pre.len(), 2);
        assert_eq!(pre[0]["hooks"][0]["command"], "audit");
        assert_eq!(pre[1]["hooks"][0]["command"], DEFAULT_HOOK_COMMAND);
    }

    #[test]
    fn a_user_narrowed_matcher_is_not_re_widened_on_reinstall() {
        // The user changed our matcher to Write-only on purpose; a second
        // install must respect that rather than appending an Edit|Write hook
        // that quietly restores the original behaviour.
        let existing = json!({
            "hooks": { "PreToolUse": [{
                "matcher": "Write",
                "hooks": [{ "type": "command", "command": DEFAULT_HOOK_COMMAND }]
            }] }
        });
        let (merged, changed) = merge_hooks(existing, DEFAULT_HOOK_COMMAND);
        assert!(changed, "PostToolUse is still missing, so something does change");
        let pre = merged["hooks"]["PreToolUse"].as_array().expect("array");
        assert_eq!(pre.len(), 1, "PreToolUse must not gain a second yunq hook");
        assert_eq!(pre[0]["matcher"], "Write");
    }

    #[test]
    fn a_non_object_settings_root_is_replaced_rather_than_panicking() {
        let (merged, changed) = merge_hooks(json!([1, 2, 3]), DEFAULT_HOOK_COMMAND);
        assert!(changed);
        assert!(merged["hooks"]["PreToolUse"].is_array());
    }

    #[test]
    fn the_shipped_policy_template_parses_and_protects_paths() {
        let policy = yunq_agent_policy::AgentPolicy::parse(POLICY_TEMPLATE).expect("template must be valid");
        assert!(policy.enabled());
        assert!(policy.evaluate(".github/workflows/ci.yml", &[]).is_denied());
        assert!(policy.evaluate("infra/main.tf", &[]).is_denied());
        assert!(!policy.evaluate("src/app.ts", &[]).is_denied());
    }

    #[test]
    fn the_shipped_policy_template_turns_on_a_stricter_ai_touched_threshold() {
        use yunq_agent_policy::{Finding, Provenance};

        let policy = yunq_agent_policy::AgentPolicy::parse(POLICY_TEMPLATE).expect("template must be valid");
        assert_eq!(policy.block_at_or_above(), yunq_rules_engine::Severity::Critical);
        assert_eq!(policy.block_at_or_above_for(Provenance::AiTouched), yunq_rules_engine::Severity::Major);

        let major_finding = [Finding {
            rule: yunq_rules_engine::RuleId::new("smells:long-method").expect("valid rule id"),
            severity: yunq_rules_engine::Severity::Major,
            message: "boom".to_string(),
            line: 1,
        }];
        assert!(
            !policy.evaluate_with_provenance("src/app.ts", &major_finding, Provenance::Unestablished).is_denied(),
            "major is below the shipped base threshold of critical"
        );
        assert!(
            policy.evaluate_with_provenance("src/app.ts", &major_finding, Provenance::AiTouched).is_denied(),
            "major meets the shipped ai_touched threshold"
        );
    }
}
