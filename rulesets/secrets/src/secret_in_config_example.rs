//! Complement of `secrets:dotenv-file-committed`: flags a real-looking
//! secret accidentally pasted into a "safe" example/template config file
//! (`.env.example`, `config.sample.yaml`, `settings.dist.json`, ...). These
//! files are meant to hold obvious placeholders, so any real credential in
//! one is a mistake — and since example files are usually the most widely
//! shared/most public part of a repo, this is treated as top severity.

use vord_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile, Span};
use vord_rules_engine::{Finding, IssueType, Rule, RuleId, RuleMetadata, Severity};

use crate::secret_literal::{CREDENTIAL_ASSIGNMENT, assignment_value, looks_like_real_secret};

/// Filename markers (substring, case-insensitive) identifying an
/// example/template config file.
const EXAMPLE_FILE_MARKERS: &[&str] = &[".example", ".sample", ".dist", ".template"];

fn is_example_config_filename(filename: &str) -> bool {
    let lower = filename.to_lowercase();
    EXAMPLE_FILE_MARKERS.iter().any(|m| lower.contains(m))
}

pub struct SecretInConfigExampleRule {
    id: RuleId,
}

impl SecretInConfigExampleRule {
    pub fn new() -> Self {
        Self {
            id: RuleId::new("secrets:secret-in-config-example").expect("valid rule id"),
        }
    }
}

impl Default for SecretInConfigExampleRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for SecretInConfigExampleRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn applies_to(&self, _language: &LanguageIdentifier) -> bool {
        true
    }

    fn default_severity(&self) -> Severity {
        Severity::Blocker
    }

    fn issue_type(&self) -> IssueType {
        IssueType::Vulnerability
    }

    fn metadata(&self) -> RuleMetadata {
        RuleMetadata {
            description: "A real-looking credential is committed inside a file meant to hold placeholder values only (.example/.sample/.dist/.template). Example/config-template files are typically the most widely shared part of a repo, so a leaked real secret here is high risk.".into(),
            tags: vec!["security".into(), "secrets".into(), "owasp-a07".into()],
            cwe: Some(798),
            produces_hotspots: false,
        }
    }

    fn check(&self, file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        if *ast.kind() != NodeKind::SourceUnit {
            return Vec::new();
        }
        let filename = file
            .path()
            .rsplit(['/', '\\'])
            .next()
            .unwrap_or(file.path());
        if !is_example_config_filename(filename) {
            return Vec::new();
        }

        let mut findings = Vec::new();
        for (idx, line) in file.content().lines().enumerate() {
            for caps in CREDENTIAL_ASSIGNMENT.captures_iter(line) {
                let value = assignment_value(&caps);
                if looks_like_real_secret(value) {
                    let line_no = (idx + 1) as u32;
                    findings.push(Finding::new(
                        "example/template config file contains a real-looking credential instead of a placeholder; replace it with an obviously-fake value",
                        Span::new(line_no, 1, line_no, line.len().max(1) as u32),
                    ));
                    break;
                }
            }
        }
        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check(path: &str, lang: LanguageIdentifier, code: &str) -> Vec<Finding> {
        let file = SourceFile::new(path, code, lang).unwrap();
        let ast = AstNode::new(
            NodeKind::SourceUnit,
            Span::new(1, 1, 1, code.len().max(1) as u32),
            code,
            vec![],
        );
        SecretInConfigExampleRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_real_secret_in_dotenv_example() {
        let code = "API_TOKEN=aG3n7Zq9Lm2XpW5vBt8FhKc1RdSy\n";
        assert_eq!(
            check(".env.example", LanguageIdentifier::bash(), code).len(),
            1
        );
    }

    #[test]
    fn flags_real_secret_in_yaml_sample_config() {
        let code = "api_key: \"Xk9pQz2mWv7RtYc4Ln8B\"\n";
        assert_eq!(
            check("config.sample.yaml", LanguageIdentifier::yaml(), code).len(),
            1
        );
    }

    #[test]
    fn ignores_placeholder_in_example_file() {
        let code = "API_TOKEN=YOUR_API_KEY\nDB_PASSWORD=changeme\n";
        assert!(check(".env.example", LanguageIdentifier::bash(), code).is_empty());
    }

    #[test]
    fn ignores_real_secret_shaped_value_outside_example_files() {
        let code = "API_TOKEN=aG3n7Zq9Lm2XpW5vBt8FhKc1RdSy\n";
        assert!(check(".env", LanguageIdentifier::bash(), code).is_empty());
    }
}
