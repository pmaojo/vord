//! Composition root for `yunq swarm` (roadmap B) — worktree-per-agent
//! isolation, per-role policy scoping and durable handoffs.
//!
//! This module is deliberately thin: every decision lives in `core/swarm`
//! (worktree/handoff schemas) or `core/agent-policy` (`RoleScope`); what's
//! here is the same kind of bridging `bin/cli::architecture_config` already
//! does for `[architecture]` — turning `yunq.toml`'s serde-facing
//! `RoleSettings` into the engine-facing types those crates actually take.

use std::path::Path;

use yunq_agent::runtime::RunOutcome;
use yunq_agent_policy::{AgentPolicy, RoleScope};
use yunq_infra_fs::{RoleSettings, WorktreeStatus, YunqConfig};
use yunq_rules_engine::RuleId;
use yunq_swarm::{Handoff, RoleWorktreeConfig, WorktreePlan};

use crate::agent::{self, AgentArgs};
use crate::hook;

/// The roles configured under `[[swarm.role]]`, or none when the repository
/// has no `yunq.toml` / no `[swarm]` table — the same fail-open convention
/// every other optional `yunq.toml` table follows.
pub fn configured_roles(root: &Path) -> Vec<RoleSettings> {
    YunqConfig::load_from_dir(root)
        .map(|c| c.swarm.roles)
        .unwrap_or_default()
}

fn find_role(roles: &[RoleSettings], name: &str) -> anyhow::Result<RoleSettings> {
    roles
        .iter()
        .find(|role| role.name == name)
        .cloned()
        .ok_or_else(|| {
            anyhow::anyhow!("no role named {name:?} — add a [[swarm.role]] entry to yunq.toml")
        })
}

fn worktree_config(role: &RoleSettings) -> RoleWorktreeConfig {
    RoleWorktreeConfig {
        name: role.name.clone(),
        worktree: role.worktree.clone(),
        branch: role.branch.clone(),
    }
}

/// A role's [`RoleScope`] — every rule id validated up front, the same way
/// `bin/cli::agent::run_config` validates `--rule` before it ever reaches
/// the policy, so a typo in `yunq.toml` is reported as a config error rather
/// than silently matching nothing.
fn role_scope(role: &RoleSettings) -> anyhow::Result<RoleScope> {
    let parse_rules = |raw: &[String]| -> anyhow::Result<Vec<RuleId>> {
        raw.iter()
            .map(|r| {
                RuleId::new(r)
                    .map_err(|_| anyhow::anyhow!("role {:?}: invalid rule id {r:?}", role.name))
            })
            .collect()
    };
    Ok(RoleScope {
        protected_paths: role
            .protected_paths
            .iter()
            .map(|p| (p.pattern.clone(), p.reason.clone()))
            .collect(),
        blocking_rules: parse_rules(&role.blocking_rules)?,
        escalate_rules: parse_rules(&role.escalate_rules)?,
    })
}

/// Where a role's worktree and branch belong, resolved against
/// `[swarm] worktree_root` (or the built-in default when unset).
pub fn worktree_plan(
    root: &Path,
    config: Option<&YunqConfig>,
    role: &RoleSettings,
) -> WorktreePlan {
    let worktree_root = config.and_then(|c| c.swarm.worktree_root.as_deref());
    yunq_swarm::plan_worktree(root, worktree_root, &worktree_config(role))
}

/// The base repository policy (same file `yunq hook` enforces), narrowed by
/// this role's own [`RoleScope`] — never the other way around, since a role
/// can only add restriction (see `AgentPolicy::with_role_scope`'s docs).
pub fn scoped_policy(root: &Path, role: &RoleSettings) -> anyhow::Result<AgentPolicy> {
    let base = hook::load_policy(root)?;
    let scope = role_scope(role)?;
    base.with_role_scope(&scope)
        .map_err(|e| anyhow::anyhow!("role {:?}: {e}", role.name))
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
    let roles = config
        .as_ref()
        .map(|c| c.swarm.roles.clone())
        .unwrap_or_default();
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

/// The configured topology's role order (roadmap B4), resolved against
/// whatever `[[swarm.role]]` entries actually exist — reported as a config
/// error the same way an undefined role or an invalid rule id already are,
/// rather than silently running nothing.
pub fn topology_order(root: &Path) -> anyhow::Result<Vec<String>> {
    let config = YunqConfig::load_from_dir(root);
    let roles = config
        .as_ref()
        .map(|c| c.swarm.roles.clone())
        .unwrap_or_default();
    let role_names: Vec<String> = roles.iter().map(|r| r.name.clone()).collect();
    let preset = config.as_ref().and_then(|c| c.swarm.topology.clone());
    let pipeline = config.as_ref().and_then(|c| c.swarm.pipeline.clone());
    yunq_swarm::resolve_topology(preset.as_deref(), pipeline.as_deref(), &role_names)
        .map_err(|e| anyhow::anyhow!("{e}"))
}

/// One role's headless run inside a topology (roadmap B4): which role it
/// was, and the same [`RunOutcome`] `yunq agent run` reports for a solo
/// session, so a caller can branch on `outcome.exit_code()` exactly as it
/// would for one.
pub struct RoleRunOutcome {
    pub role: String,
    pub outcome: RunOutcome,
}

/// Drives every role in the configured topology through one headless `yunq
/// agent` run apiece, in order: create (or attach to) the role's worktree,
/// fold in whatever the previous role handed off, run the task under this
/// role's own scoped policy, then queue a handoff summarizing the outcome for
/// the next role in line. Stops at the first role whose run does not
/// complete — handing an incomplete/failed run's baggage to the next role
/// would only compound whatever went wrong, and `RunOutcome::exit_code`
/// already gives the caller a precise reason to stop on.
pub async fn topology_run(root: &Path, task: &str) -> anyhow::Result<Vec<RoleRunOutcome>> {
    let order = topology_order(root)?;
    let roles = configured_roles(root);
    let config = YunqConfig::load_from_dir(root);

    let mut results = Vec::new();
    for (position, role_name) in order.iter().enumerate() {
        let role = find_role(&roles, role_name)?;
        let plan = worktree_plan(root, config.as_ref(), &role);
        ensure_worktree(root, &plan)?;

        let mut role_task = format!("{task} (role: {role_name})");
        for handoff in take_inbox(root, role_name)? {
            role_task.push_str(&format!(
                "\n\nHandoff from {}: {}",
                handoff.from_role, handoff.summary
            ));
        }

        let policy = scoped_policy(&plan.path, &role)?;
        let args = AgentArgs {
            task: role_task,
            scope: ".".to_string(),
            rule: None,
            max_turns: None,
            max_tokens: None,
            model: None,
        };
        let task_desc = args.task.clone();
        let outcome = match agent::run_with_policy(&plan.path, args, policy).await {
            Ok(res) => res,
            Err(err) => {
                eprintln!("\nyunq swarm: LLM provider unavailable for role [{role_name}]: {err}");
                eprintln!(">>> SWARM ASSISTANT HANDOFF PROMPT (role: {role_name}) <<<");
                eprintln!("Worktree: {}", plan.path.display());
                eprintln!("Task: {}", task_desc);
                eprintln!("Policy Scope: blocking_rules={:?}, protected_paths={:?}", role.blocking_rules, role.protected_paths);
                eprintln!(">>> END PROMPT <<<\n");
                return Err(err);
            }
        };

        let completed = matches!(outcome, RunOutcome::Completed { .. });
        if !completed {
            eprintln!("\nyunq swarm: LLM provider unavailable/failed for role [{role_name}]: {}", outcome.describe());
            eprintln!(">>> SWARM ASSISTANT HANDOFF PROMPT (role: {role_name}) <<<");
            eprintln!("Worktree: {}", plan.path.display());
            eprintln!("Task: {}", task_desc);
            eprintln!("Policy Scope: blocking_rules={:?}, protected_paths={:?}", role.blocking_rules, role.protected_paths);
            eprintln!(">>> END PROMPT <<<\n");
        }

        if let Some(next) = order.get(position + 1) {
            let summary = format!("{} — {}", role_name, outcome.describe());
            handoff_send(root, role_name, next, &summary)?;
        }
        results.push(RoleRunOutcome {
            role: role_name.clone(),
            outcome,
        });
        if !completed {
            break;
        }
    }
    Ok(results)
}

/// Creates this role's worktree if it doesn't already have one — `yunq swarm
/// worktree-create` stays the explicit, one-role-at-a-time entry point;
/// this is what lets `topology_run` re-drive the same pipeline on a later
/// run without failing on "worktree already exists".
fn ensure_worktree(root: &Path, plan: &WorktreePlan) -> anyhow::Result<()> {
    let existing = yunq_infra_fs::list_worktrees(root)?;
    let already_there = existing.iter().any(|w| Path::new(&w.path) == plan.path);
    if already_there {
        return Ok(());
    }
    yunq_infra_fs::create_worktree(root, plan, "HEAD")?;
    Ok(())
}

/// Delivers the outbox, then drains and acknowledges everything waiting for
/// this role — a topology step's task should see a handoff exactly once,
/// same as `yunq swarm handoff-inbox` followed by `handoff-ack` would give an
/// operator driving the pipeline by hand.
fn take_inbox(root: &Path, role_name: &str) -> anyhow::Result<Vec<Handoff>> {
    handoff_deliver(root)?;
    let waiting = handoff_inbox(root, role_name)?;
    for handoff in &waiting {
        handoff_ack(root, role_name, &handoff.id)?;
    }
    Ok(waiting)
}

pub fn worktree_create(
    root: &Path,
    role_name: &str,
    base_ref: &str,
) -> anyhow::Result<WorktreePlan> {
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
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!("{from_role}-{to_role}-{nanos}")
}

pub fn handoff_send(
    root: &Path,
    from_role: &str,
    to_role: &str,
    summary: &str,
) -> anyhow::Result<Handoff> {
    let id = generate_handoff_id(from_role, to_role);
    let handoff = Handoff::new(
        id,
        from_role,
        to_role,
        summary,
        chrono::Utc::now().timestamp(),
    );
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
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&root).unwrap();
        root.canonicalize().unwrap_or(root)
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
    fn topology_order_is_unconfigured_by_default() {
        let root = temp_root();
        assert!(topology_order(&root).is_err());
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn topology_order_resolves_a_named_preset_against_configured_roles() {
        let root = temp_root();
        std::fs::write(
            root.join("yunq.toml"),
            r#"
[swarm]
topology = "two-pack"

[[swarm.role]]
name = "coder"

[[swarm.role]]
name = "reviewer"
"#,
        )
        .unwrap();

        assert_eq!(topology_order(&root).unwrap(), vec!["coder", "reviewer"]);
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn topology_order_reports_a_preset_role_that_was_never_configured() {
        let root = temp_root();
        std::fs::write(
            root.join("yunq.toml"),
            "[swarm]\ntopology = \"two-pack\"\n\n[[swarm.role]]\nname = \"coder\"\n",
        )
        .unwrap();

        let err = topology_order(&root).unwrap_err();
        assert!(err.to_string().contains("reviewer"), "{err}");
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn an_explicit_pipeline_outranks_a_named_topology_preset() {
        let root = temp_root();
        std::fs::write(
            root.join("yunq.toml"),
            r#"
[swarm]
topology = "two-pack"
pipeline = ["qa", "coder"]

[[swarm.role]]
name = "qa"

[[swarm.role]]
name = "coder"
"#,
        )
        .unwrap();

        assert_eq!(topology_order(&root).unwrap(), vec!["qa", "coder"]);
        std::fs::remove_dir_all(&root).ok();
    }

    #[tokio::test]
    async fn topology_run_reports_the_same_config_error_topology_order_would() {
        let root = temp_root();
        assert!(topology_run(&root, "ship it").await.is_err());
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
        let waiting = handoff_inbox(&root, "qa").unwrap();
        assert!(waiting.is_empty());
        std::fs::remove_dir_all(&root).ok();
    }
}

pub fn run_swarm_tui(root: &Path) -> anyhow::Result<()> {
    use crossterm::event::{self, Event, KeyCode};
    use crossterm::execute;
    use crossterm::terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode};
    use ratatui::Terminal;
    use ratatui::backend::CrosstermBackend;
    use ratatui::layout::{Constraint, Direction, Layout};
    use ratatui::style::{Color, Modifier, Style};
    use ratatui::text::{Line, Span};
    use ratatui::widgets::{Block, Borders, List, ListItem, Paragraph};

    enable_raw_mode()?;
    let mut stdout = std::io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let res = (|| -> anyhow::Result<()> {
        loop {
            let roles = configured_roles(root);
            let topology = topology_order(root).unwrap_or_default();

            terminal.draw(|f| {
                let chunks = Layout::default()
                    .direction(Direction::Vertical)
                    .constraints([
                        Constraint::Length(3),
                        Constraint::Min(10),
                        Constraint::Length(3),
                    ])
                    .split(f.area());

                let header = Paragraph::new(Line::from(vec![
                    Span::styled("yunq swarm ", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
                    Span::raw("— Interactive Spec-Driven Swarm & Worktree Dashboard (Offline / LLM-less)"),
                ]))
                .block(Block::default().borders(Borders::ALL).title(" Topology "));
                f.render_widget(header, chunks[0]);

                let body_chunks = Layout::default()
                    .direction(Direction::Horizontal)
                    .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
                    .split(chunks[1]);

                let mut role_items = Vec::new();
                for r in &roles {
                    let plan = worktree_plan(root, None, r);
                    role_items.push(ListItem::new(vec![
                        Line::styled(format!("Role: {}", r.name), Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
                        Line::raw(format!("  Worktree: {}", plan.path.display())),
                        Line::raw(format!("  Branch: {}", plan.branch)),
                        Line::raw(format!("  Protected Paths: {:?}", r.protected_paths.len())),
                        Line::raw(format!("  Blocking Rules: {:?}", r.blocking_rules.len())),
                        Line::raw(""),
                    ]));
                }
                let roles_list = List::new(role_items)
                    .block(Block::default().borders(Borders::ALL).title(format!(" Roles ({}) ", topology.join(" -> "))));
                f.render_widget(roles_list, body_chunks[0]);

                let mut handoff_items = Vec::new();
                for r in &roles {
                    if let Ok(inbox) = handoff_inbox(root, &r.name) {
                        for h in inbox {
                            handoff_items.push(ListItem::new(Line::styled(
                                format!("[INBOX: {}] From {}: {}", r.name, h.from_role, h.summary),
                                Style::default().fg(Color::Green),
                            )));
                        }
                    }
                }
                if handoff_items.is_empty() {
                    handoff_items.push(ListItem::new(Line::styled(
                        "No pending handoffs. All role inboxes clear.",
                        Style::default().fg(Color::DarkGray),
                    )));
                }
                let handoffs_list = List::new(handoff_items)
                    .block(Block::default().borders(Borders::ALL).title(" Handoff Queue "));
                f.render_widget(handoffs_list, body_chunks[1]);

                let footer = Paragraph::new(Line::from(vec![
                    Span::styled("[d]", Style::default().fg(Color::Yellow)),
                    Span::raw(" Deliver Handoffs | "),
                    Span::styled("[r]", Style::default().fg(Color::Yellow)),
                    Span::raw(" Refresh | "),
                    Span::styled("[q / Esc]", Style::default().fg(Color::Yellow)),
                    Span::raw(" Quit TUI"),
                ]))
                .block(Block::default().borders(Borders::ALL).title(" Controls "));
                f.render_widget(footer, chunks[2]);
            })?;

            if event::poll(std::time::Duration::from_millis(250))? {
                if let Event::Key(key) = event::read()? {
                    match key.code {
                        KeyCode::Char('q') | KeyCode::Esc => break,
                        KeyCode::Char('d') => {
                            let _ = handoff_deliver(root);
                        }
                        _ => {}
                    }
                }
            }
        }
        Ok(())
    })();

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;
    res
}
