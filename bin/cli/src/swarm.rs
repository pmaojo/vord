//! Composition root for `yunq swarm` (roadmap B) — worktree-per-agent
//! isolation, per-role policy scoping and durable handoffs.
//!
//! This module is deliberately thin: every decision lives in `core/swarm`
//! (worktree/handoff schemas) or `core/agent-policy` (`RoleScope`); what's
//! here is the same kind of bridging `bin/cli::architecture_config` already
//! does for `[architecture]` — turning `yunq.toml`'s serde-facing
//! `RoleSettings` into the engine-facing types those crates actually take.

use std::path::Path;

use yunq_agent_policy::{AgentPolicy, RoleScope};
use yunq_infra_fs::{RoleSettings, WorktreeStatus, YunqConfig};
use yunq_rules_engine::RuleId;
use yunq_swarm::{Handoff, RoleWorktreeConfig, WorktreePlan};

use crate::hook;

/// The roles configured under `[[swarm.role]]`, or none when the repository
/// has no `yunq.toml` / no `[swarm]` table — the same fail-open convention
/// every other optional `yunq.toml` table follows.
pub fn configured_roles(root: &Path) -> Vec<RoleSettings> {
    YunqConfig::load_from_dir(root).map(|c| c.swarm.roles).unwrap_or_default()
}

fn find_role(roles: &[RoleSettings], name: &str) -> anyhow::Result<RoleSettings> {
    roles
        .iter()
        .find(|role| role.name == name)
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("no role named {name:?} — add a [[swarm.role]] entry to yunq.toml"))
}

fn worktree_config(role: &RoleSettings) -> RoleWorktreeConfig {
    RoleWorktreeConfig { name: role.name.clone(), worktree: role.worktree.clone(), branch: role.branch.clone() }
}

/// A role's [`RoleScope`] — every rule id validated up front, the same way
/// `bin/cli::agent::run_config` validates `--rule` before it ever reaches
/// the policy, so a typo in `yunq.toml` is reported as a config error rather
/// than silently matching nothing.
fn role_scope(role: &RoleSettings) -> anyhow::Result<RoleScope> {
    let parse_rules = |raw: &[String]| -> anyhow::Result<Vec<RuleId>> {
        raw.iter()
            .map(|r| RuleId::new(r).map_err(|_| anyhow::anyhow!("role {:?}: invalid rule id {r:?}", role.name)))
            .collect()
    };
    Ok(RoleScope {
        protected_paths: role.protected_paths.iter().map(|p| (p.pattern.clone(), p.reason.clone())).collect(),
        blocking_rules: parse_rules(&role.blocking_rules)?,
        escalate_rules: parse_rules(&role.escalate_rules)?,
    })
}

/// Where a role's worktree and branch belong, resolved against
/// `[swarm] worktree_root` (or the built-in default when unset).
pub fn worktree_plan(root: &Path, config: Option<&YunqConfig>, role: &RoleSettings) -> WorktreePlan {
    let worktree_root = config.and_then(|c| c.swarm.worktree_root.as_deref());
    yunq_swarm::plan_worktree(root, worktree_root, &worktree_config(role))
}

/// The base repository policy (same file `yunq hook` enforces), narrowed by
/// this role's own [`RoleScope`] — never the other way around, since a role
/// can only add restriction (see `AgentPolicy::with_role_scope`'s docs).
pub fn scoped_policy(root: &Path, role: &RoleSettings) -> anyhow::Result<AgentPolicy> {
    let base = hook::load_policy(root)?;
    let scope = role_scope(role)?;
    base.with_role_scope(&scope).map_err(|e| anyhow::anyhow!("role {:?}: {e}", role.name))
}

/// One line of `yunq swarm roles` output: the resolved worktree plan plus a
/// count of what this role adds on top of the base policy, so a reviewer can
/// see the scope narrowing without diffing the whole compiled policy.
pub struct RoleReport {
    pub name: String,
    pub plan: WorktreePlan,
    pub extra_protected_paths: usize,
    pub extra_blocking_rules: usize,
    pub extra_escalate_rules: usize,
}

pub fn list_roles(root: &Path) -> anyhow::Result<Vec<RoleReport>> {
    let config = YunqConfig::load_from_dir(root);
    let roles = config.as_ref().map(|c| c.swarm.roles.clone()).unwrap_or_default();
    roles
        .iter()
        .map(|role| {
            // Validated here (not just planned) so a typo'd rule id in one
            // role's scope is reported by `yunq swarm roles` instead of
            // surfacing only when that role's worktree first gets used.
            role_scope(role)?;
            Ok(RoleReport {
                name: role.name.clone(),
                plan: worktree_plan(root, config.as_ref(), role),
                extra_protected_paths: role.protected_paths.len(),
                extra_blocking_rules: role.blocking_rules.len(),
                extra_escalate_rules: role.escalate_rules.len(),
            })
        })
        .collect()
}

pub fn worktree_create(root: &Path, role_name: &str, base_ref: &str) -> anyhow::Result<WorktreePlan> {
    let roles = configured_roles(root);
    let role = find_role(&roles, role_name)?;
    let config = YunqConfig::load_from_dir(root);
    let plan = worktree_plan(root, config.as_ref(), &role);
    yunq_infra_fs::create_worktree(root, &plan, base_ref)?;
    Ok(plan)
}

pub fn worktree_remove(root: &Path, role_name: &str, force: bool) -> anyhow::Result<WorktreePlan> {
    let roles = configured_roles(root);
    let role = find_role(&roles, role_name)?;
    let config = YunqConfig::load_from_dir(root);
    let plan = worktree_plan(root, config.as_ref(), &role);
    yunq_infra_fs::remove_worktree(root, &plan, force)?;
    Ok(plan)
}

pub fn worktree_list(root: &Path) -> anyhow::Result<Vec<WorktreeStatus>> {
    Ok(yunq_infra_fs::list_worktrees(root)?)
}

/// Generates a handoff id unique enough for one repository's queue: a sender
/// retrying the identical logical handoff should reuse an id it already
/// has (see `yunq_infra_fs::send`'s overwrite-not-duplicate contract) rather
/// than call this again.
fn generate_handoff_id(from_role: &str, to_role: &str) -> String {
    let nanos =
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_nanos();
    format!("{from_role}-{to_role}-{nanos}")
}

pub fn handoff_send(root: &Path, from_role: &str, to_role: &str, summary: &str) -> anyhow::Result<Handoff> {
    let id = generate_handoff_id(from_role, to_role);
    let handoff = Handoff::new(id, from_role, to_role, summary, chrono::Utc::now().timestamp());
    yunq_infra_fs::send_handoff(root, &handoff)?;
    Ok(handoff)
}

pub fn handoff_deliver(root: &Path) -> anyhow::Result<Vec<Handoff>> {
    Ok(yunq_infra_fs::deliver(root)?)
}

pub fn handoff_inbox(root: &Path, role_name: &str) -> anyhow::Result<Vec<Handoff>> {
    Ok(yunq_infra_fs::inbox(root, role_name)?)
}

pub fn handoff_ack(root: &Path, role_name: &str, id: &str) -> anyhow::Result<()> {
    Ok(yunq_infra_fs::ack(root, role_name, id)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_root() -> std::path::PathBuf {
        let root = std::env::temp_dir().join(format!(
            "yunq-cli-swarm-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        std::fs::create_dir_all(&root).unwrap();
        root
    }

    #[test]
    fn a_repository_with_no_yunq_toml_has_no_configured_roles() {
        let root = temp_root();
        assert!(configured_roles(&root).is_empty());
        assert!(list_roles(&root).unwrap().is_empty());
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn a_configured_role_resolves_a_worktree_plan_and_scope_counts() {
        let root = temp_root();
        std::fs::write(
            root.join("yunq.toml"),
            r#"
[[swarm.role]]
name = "qa"
blocking_rules = ["owasp:eval-usage"]

[[swarm.role.protected_paths]]
pattern = "**"
reason = "QA is read-only"
"#,
        )
        .unwrap();

        let roles = list_roles(&root).unwrap();
        assert_eq!(roles.len(), 1);
        assert_eq!(roles[0].name, "qa");
        assert_eq!(roles[0].plan.branch, "yunq/swarm/qa");
        assert_eq!(roles[0].extra_protected_paths, 1);
        assert_eq!(roles[0].extra_blocking_rules, 1);

        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn an_undefined_role_is_reported_rather_than_silently_planned() {
        let root = temp_root();
        assert!(worktree_create(&root, "ghost", "main").is_err());
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn scoped_policy_denies_what_the_role_adds_on_top_of_the_base() {
        let root = temp_root();
        std::fs::write(
            root.join("yunq.toml"),
            "[[swarm.role]]\nname = \"qa\"\nblocking_rules = [\"smells:long-method\"]\n",
        )
        .unwrap();
        let roles = configured_roles(&root);
        let role = find_role(&roles, "qa").unwrap();

        let policy = scoped_policy(&root, &role).unwrap();
        let finding = yunq_agent_policy::Finding {
            rule: RuleId::new("smells:long-method").unwrap(),
            severity: yunq_rules_engine::Severity::Minor,
            message: "too long".to_string(),
            line: 1,
        };
        assert!(policy.evaluate("a.py", &[finding]).is_denied());

        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn handoffs_round_trip_through_send_deliver_inbox_and_ack() {
        let root = temp_root();
        let handoff = handoff_send(&root, "coder", "qa", "please review").unwrap();
        let delivered = handoff_deliver(&root).unwrap();
        assert_eq!(delivered, vec![handoff.clone()]);

        let waiting = handoff_inbox(&root, "qa").unwrap();
        assert_eq!(waiting, vec![handoff.clone()]);

        handoff_ack(&root, "qa", &handoff.id).unwrap();
        assert!(handoff_inbox(&root, "qa").unwrap().is_empty());

        std::fs::remove_dir_all(&root).ok();
    }
}
