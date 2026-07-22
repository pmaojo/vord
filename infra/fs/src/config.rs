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
                let key = key.trim();
                let val = val.trim().to_string();
                match key {
                    "sonar.projectKey" => config.project.key = Some(val),
                    "sonar.projectName" => config.project.name = Some(val),
                    "sonar.projectVersion" => config.project.version = Some(val),
                    "sonar.sources" => {
                        config.analysis.sources = Some(val.split(',').map(|s| s.trim().to_string()).collect());
                    }
                    "sonar.exclusions" => {
                        config.analysis.exclusions = Some(val.split(',').map(|s| s.trim().to_string()).collect());
                    }
                    "sonar.inclusions" => {
                        config.analysis.inclusions = Some(val.split(',').map(|s| s.trim().to_string()).collect());
                    }
                    _ => {}
                }
            }
        }
        config
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_yunq_toml() {
        let toml_content = r#"
[project]
key = "my-awesome-repo"
name = "My Awesome Repository"
version = "1.2.3"

[analysis]
sources = ["src", "lib"]
exclusions = ["**/vendor/**", "**/fixtures/**"]
"#;
        let config: YunqConfig = toml::from_str(toml_content).unwrap();
        assert_eq!(config.project.key.as_deref(), Some("my-awesome-repo"));
        assert_eq!(config.analysis.sources.as_ref().unwrap().len(), 2);
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
