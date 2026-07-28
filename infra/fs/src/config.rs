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
}
