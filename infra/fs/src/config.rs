//! Configuration loader for `yunq.toml` / `.yunq.toml` and legacy `sonar-project.properties`.

use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct YunqConfig {
    #[serde(default)]
    pub project: ProjectConfig,
    #[serde(default)]
    pub analysis: AnalysisConfig,
    #[serde(default)]
    pub rules: RulesConfig,
    #[serde(default)]
    pub duplication: DuplicationSettings,
    #[serde(default)]
    pub architecture: ArchitectureSettings,
    #[serde(default)]
    pub agent: AgentSettings,
    #[serde(default)]
    pub swarm: SwarmSettings,
}

/// `[agent]` in `yunq.toml` — the `yunq agent` runtime's limits.
///
/// Not to be confused with `[agent]` in **`yunq-policy.toml`**, which is the
/// Agent Permission Policy: what an agent may *do*. This table is only what a
/// run may *spend*. They are separate files because they answer to separate
/// people — the policy is a security control a reviewer owns, these are
/// operational knobs whoever runs the agent owns.
///
/// Every field is optional and falls back to `yunq_agent`'s own default, so a
/// project states only what it wants changed.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct AgentSettings {
    /// Model turns one run may take (runtime default 40).
    pub max_turns: Option<u32>,
    /// Tokens one run may spend across all turns (runtime default 500000).
    pub max_tokens: Option<u64>,
    /// How many times the analyzer may send the model back before the run is
    /// reported incomplete (runtime default 3).
    pub max_rejections: Option<u32>,
    /// Programs the `run` tool may execute. Replaces the built-in list
    /// outright rather than extending it — an allowlist you have to read two
    /// places to understand is not one.
    pub allowed_commands: Option<Vec<String>>,
    /// Wall-clock seconds a `run` command may take before it is killed
    /// (adapter default 300).
    pub command_timeout_secs: Option<u64>,
}

/// `[swarm]` in `yunq.toml` — worktree-per-agent isolation and role config
/// for `yunq swarm` (roadmap B1). Every role gets its own git worktree so
/// concurrent agents never contend on the index, and its own [`RoleScope`]
/// policy narrowing (roadmap B3) so a role's access is scoped to what it
/// actually needs — the cleaner may not touch `.github/workflows/**`, QA
/// gets no write access at all.
///
/// Absent (or with no `[[swarm.role]]` entries) means `yunq swarm` has
/// nothing configured to run — the same opt-in-until-configured convention
/// `[architecture]` and `[duplication]` already use.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct SwarmSettings {
    /// Directory (repository-relative) worktrees are created under.
    /// Defaults to `.yunq/worktrees` when unset.
    pub worktree_root: Option<String>,
    #[serde(default, rename = "role")]
    pub roles: Vec<RoleSettings>,
}

/// One `[[swarm.role]]` entry: a named role, its own worktree/branch naming,
/// and the access restrictions layered onto the base `yunq-policy.toml` for
/// writes made from inside that role's worktree.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct RoleSettings {
    pub name: String,
    /// Worktree directory for this role, relative to `worktree_root`.
    /// Defaults to the role's own `name` when unset.
    pub worktree: Option<String>,
    /// Branch the worktree is created on. Defaults to `yunq/swarm/<name>`
    /// when unset.
    pub branch: Option<String>,
    /// Extra paths this role may never write to, beyond the base policy's
    /// own `[[protected_path]]` entries.
    #[serde(default)]
    pub protected_paths: Vec<RoleProtectedPath>,
    /// Extra rule ids this role may never introduce, beyond the base
    /// policy's `blocking_rules`.
    #[serde(default)]
    pub blocking_rules: Vec<String>,
    /// Extra rule ids this role's writes escalate to, beyond the base
    /// policy's `escalate_rules`.
    #[serde(default)]
    pub escalate_rules: Vec<String>,
}

/// Same shape as `yunq-policy.toml`'s `[[protected_path]]`, declared inline
/// under a role instead of in the policy file — a role's scope lives beside
/// its other settings in `yunq.toml`, not split across two files.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RoleProtectedPath {
    pub pattern: String,
    pub reason: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProjectConfig {
    pub key: Option<String>,
    pub name: Option<String>,
    pub version: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct AnalysisConfig {
    pub sources: Option<Vec<String>>,
    pub exclusions: Option<Vec<String>>,
    pub inclusions: Option<Vec<String>>,
    pub profile: Option<String>,
}

/// `[duplication]` in `yunq.toml`. Every field is optional and falls back
/// to the engine default, so a project only states what it wants changed.
/// These were hardcoded before, which meant a codebase whose shape did not
/// suit the defaults had no recourse.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct DuplicationSettings {
    /// Smallest clone worth reporting, in source lines (engine default 10).
    pub min_lines: Option<usize>,
    /// Consecutive statements per hashed block (engine default 5) — the
    /// granularity candidate matches are found at, before extension.
    pub block_size: Option<usize>,
    /// Erase identifier names before hashing, so a copied-and-renamed block
    /// still matches ("Type-2" clones). Off by default.
    pub normalize_identifiers: Option<bool>,
    /// Let test code participate in duplication detection. Off by default —
    /// repetition in a test suite is usually deliberate.
    pub include_test_code: Option<bool>,
    /// Most declaration boundaries one reported clone may span (engine
    /// default 1). Raise it to see regions that cover several adjacent
    /// declarations, e.g. a whole trait implementation.
    pub max_declarations_spanned: Option<usize>,
}

/// `[architecture]` in `yunq.toml` — declared component boundaries (roadmap
/// D2). Components are derived automatically from directory topology
/// (`yunq_import_graph::component_of`, roadmap D1), so there is nothing to
/// declare here except the edges themselves. All three lists default to
/// empty, meaning no boundaries declared — the architecture rule is then a
/// silent no-op, the same fail-open convention `[duplication]` follows.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ArchitectureSettings {
    /// Once non-empty, switches the check into whitelist mode: any
    /// component-level edge not listed here is a violation.
    #[serde(default)]
    pub allowed_dependencies: Vec<DependencyEdgeConfig>,
    /// Component-level edges that are always a violation, regardless of
    /// `allowed_dependencies`.
    #[serde(default)]
    pub forbidden_dependencies: Vec<DependencyEdgeConfig>,
    /// Specific edges exempted from both lists above — the escape hatch for
    /// a deliberate, reviewed exception to an otherwise-general rule.
    #[serde(default)]
    pub exceptions: Vec<DependencyEdgeConfig>,
}

/// One `{ from = "...", to = "..." }` entry in an `[architecture]` list.
/// `from`/`to` name a component (`component_of`'s output, e.g.
/// `"core/rules-engine"`) or a whole tier with no component-name segment
/// (e.g. `"core"`, matching every component under it) — see
/// `yunq_import_graph::DependencyEdge` for the matching rule.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct DependencyEdgeConfig {
    pub from: String,
    pub to: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct RulesConfig {
    #[serde(default)]
    pub custom: Vec<CustomRuleConfig>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CustomRuleConfig {
    pub id: String,
    pub message: String,
    pub pattern: String,
    #[serde(default = "default_severity_str")]
    pub severity: String,
}

fn default_severity_str() -> String {
    "major".to_string()
}

impl YunqConfig {
    /// Attempts to load configuration from `yunq.toml`, `.yunq.toml`, or `sonar-project.properties`.
    pub fn load_from_dir(dir: &Path) -> Option<Self> {
        let yunq_toml = dir.join("yunq.toml");
        if yunq_toml.exists() {
            if let Ok(content) = fs::read_to_string(&yunq_toml) {
                if let Ok(config) = toml::from_str::<YunqConfig>(&content) {
                    return Some(config);
                }
            }
        }

        let dot_yunq_toml = dir.join(".yunq.toml");
        if dot_yunq_toml.exists() {
            if let Ok(content) = fs::read_to_string(&dot_yunq_toml) {
                if let Ok(config) = toml::from_str::<YunqConfig>(&content) {
                    return Some(config);
                }
            }
        }

        let sonar_props = dir.join("sonar-project.properties");
        if sonar_props.exists() {
            if let Ok(content) = fs::read_to_string(&sonar_props) {
                return Some(Self::parse_sonar_properties(&content));
            }
        }

        None
    }

    pub fn parse_sonar_properties(content: &str) -> Self {
        let mut config = YunqConfig::default();
        for line in content.lines() {
            let line = line.trim();
            if line.starts_with('#') || line.is_empty() {
                continue;
            }
            if let Some((key, val)) = line.split_once('=') {
                apply_sonar_property(&mut config, key.trim(), val.trim());
            }
        }
        config
    }
}

/// Splits a comma-joined `sonar.*` property value (`"src,lib"`) into its
/// trimmed parts.
fn split_csv(val: &str) -> Vec<String> {
    val.split(',').map(|s| s.trim().to_string()).collect()
}

fn apply_sonar_property(config: &mut YunqConfig, key: &str, val: &str) {
    match key {
        "sonar.projectKey" => config.project.key = Some(val.to_string()),
        "sonar.projectName" => config.project.name = Some(val.to_string()),
        "sonar.projectVersion" => config.project.version = Some(val.to_string()),
        "sonar.sources" => config.analysis.sources = Some(split_csv(val)),
        "sonar.exclusions" => config.analysis.exclusions = Some(split_csv(val)),
        "sonar.inclusions" => config.analysis.inclusions = Some(split_csv(val)),
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_yunq_toml_with_custom_rules() {
        let toml_content = r#"
[project]
key = "my-awesome-repo"
name = "My Awesome Repository"
version = "1.2.3"

[analysis]
sources = ["src", "lib"]

[[rules.custom]]
id = "custom:no-console-log"
message = "Do not leave console.log in production code"
pattern = "console.log"
severity = "minor"
"#;
        let config: YunqConfig = toml::from_str(toml_content).unwrap();
        assert_eq!(config.project.key.as_deref(), Some("my-awesome-repo"));
        assert_eq!(config.rules.custom.len(), 1);
        assert_eq!(config.rules.custom[0].pattern, "console.log");
        assert!(config.architecture.forbidden_dependencies.is_empty());
    }

    #[test]
    fn parses_sonar_properties() {
        let props = r#"
# Sonar project configuration
sonar.projectKey=legacy-sonar-key
sonar.projectName=Legacy App
sonar.sources=src,lib
sonar.exclusions=**/vendor/**
"#;
        let config = YunqConfig::parse_sonar_properties(props);
        assert_eq!(config.project.key.as_deref(), Some("legacy-sonar-key"));
        assert_eq!(config.project.name.as_deref(), Some("Legacy App"));
        assert_eq!(config.analysis.sources.unwrap(), vec!["src", "lib"]);
    }

    #[test]
    fn parses_architecture_boundaries() {
        let toml_content = r#"
[[architecture.allowed_dependencies]]
from = "bin"
to = "core"

[[architecture.forbidden_dependencies]]
from = "core"
to = "infra"

[[architecture.exceptions]]
from = "core/legacy"
to = "infra"
"#;
        let config: YunqConfig = toml::from_str(toml_content).unwrap();
        assert_eq!(config.architecture.allowed_dependencies.len(), 1);
        assert_eq!(config.architecture.allowed_dependencies[0].from, "bin");
        assert_eq!(config.architecture.forbidden_dependencies[0].to, "infra");
        assert_eq!(config.architecture.exceptions[0].from, "core/legacy");
    }

    #[test]
    fn architecture_table_is_optional() {
        let config: YunqConfig = toml::from_str("[project]\nkey = \"x\"\n").unwrap();
        assert_eq!(config.architecture, ArchitectureSettings::default());
    }

    #[test]
    fn parses_the_agent_runtime_limits() {
        let toml_content = r#"
[agent]
max_turns = 12
max_tokens = 250000
allowed_commands = ["cargo", "just"]
command_timeout_secs = 60
"#;
        let config: YunqConfig = toml::from_str(toml_content).unwrap();
        assert_eq!(config.agent.max_turns, Some(12));
        assert_eq!(config.agent.max_tokens, Some(250_000));
        assert_eq!(config.agent.allowed_commands.as_deref(), Some(["cargo".to_string(), "just".to_string()].as_slice()));
        assert_eq!(config.agent.command_timeout_secs, Some(60));
        assert_eq!(config.agent.max_rejections, None, "an unset field stays unset rather than defaulting to zero");
    }

    #[test]
    fn the_agent_table_is_optional() {
        let config: YunqConfig = toml::from_str("[project]\nkey = \"x\"\n").unwrap();
        assert_eq!(config.agent, AgentSettings::default());
    }

    #[test]
    fn parses_swarm_roles() {
        let toml_content = r#"
[swarm]
worktree_root = ".yunq/worktrees"

[[swarm.role]]
name = "coder"

[[swarm.role]]
name = "qa"
branch = "yunq/swarm/qa-custom"
blocking_rules = ["owasp:eval-usage"]
escalate_rules = ["smells:god-class"]

[[swarm.role.protected_paths]]
pattern = "**"
reason = "QA is read-only"
"#;
        let config: YunqConfig = toml::from_str(toml_content).unwrap();
        assert_eq!(config.swarm.worktree_root.as_deref(), Some(".yunq/worktrees"));
        assert_eq!(config.swarm.roles.len(), 2);
        assert_eq!(config.swarm.roles[0].name, "coder");
        assert!(config.swarm.roles[0].protected_paths.is_empty());
        let qa = &config.swarm.roles[1];
        assert_eq!(qa.name, "qa");
        assert_eq!(qa.branch.as_deref(), Some("yunq/swarm/qa-custom"));
        assert_eq!(qa.blocking_rules, vec!["owasp:eval-usage".to_string()]);
        assert_eq!(qa.escalate_rules, vec!["smells:god-class".to_string()]);
        assert_eq!(qa.protected_paths.len(), 1);
        assert_eq!(qa.protected_paths[0].pattern, "**");
    }

    #[test]
    fn the_swarm_table_is_optional() {
        let config: YunqConfig = toml::from_str("[project]\nkey = \"x\"\n").unwrap();
        assert_eq!(config.swarm, SwarmSettings::default());
        assert!(config.swarm.roles.is_empty());
    }
}
