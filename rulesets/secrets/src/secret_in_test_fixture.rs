//! Flags a secret-shaped literal assigned to a credential-named variable
//! inside a test/spec/fixture/mock file. Lower risk than a secret in
//! production code (test credentials are usually throwaway), but still
//! worth flagging — a real secret sometimes gets pasted into a fixture by
//! mistake, or a fixture value gets reused as a real one later.

use vord_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile, Span};
use vord_rules_engine::{Finding, IssueType, Rule, RuleId, RuleMetadata, Severity};

use crate::secret_literal::{CREDENTIAL_ASSIGNMENT, assignment_value, looks_like_real_secret};

/// Path segments (case-insensitive, substring match against the whole
/// forward-slash-normalized path) that mark a file as test-related.
const TEST_PATH_MARKERS: &[&str] = &["test", "spec", "fixture", "__mocks__", "__fixtures__"];

fn is_test_related_path(path: &str) -> bool {
    let normalized = path.replace('\\', "/").to_lowercase();
    TEST_PATH_MARKERS.iter().any(|m| normalized.contains(m))
}

pub struct SecretInTestFixtureRule {
    id: RuleId,
}

impl SecretInTestFixtureRule {
    pub fn new() -> Self {
        Self {
            id: RuleId::new("secrets:secret-in-test-fixture").expect("valid rule id"),
        }
    }
}

impl Default for SecretInTestFixtureRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for SecretInTestFixtureRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn applies_to(&self, _language: &LanguageIdentifier) -> bool {
        true
    }

    fn default_severity(&self) -> Severity {
        Severity::Minor
    }

    fn issue_type(&self) -> IssueType {
        IssueType::Vulnerability
    }

    fn metadata(&self) -> RuleMetadata {
        RuleMetadata {
            description: "A test/spec/fixture/mock file assigns a real-looking secret to a credential-named variable. Prefer an obviously-fake placeholder value in fixtures, even for throwaway test credentials.".into(),
            tags: vec!["security".into(), "secrets".into(), "owasp-a07".into()],
            cwe: Some(798),
            produces_hotspots: false,
        }
    }

    fn check(&self, file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        if *ast.kind() != NodeKind::SourceUnit {
            return Vec::new();
        }
        if !is_test_related_path(file.path()) {
            return Vec::new();
        }

        let mut findings = Vec::new();
        for (idx, line) in file.content().lines().enumerate() {
            for caps in CREDENTIAL_ASSIGNMENT.captures_iter(line) {
                let value = assignment_value(&caps);
                if looks_like_real_secret(value) {
                    let line_no = (idx + 1) as u32;
                    findings.push(Finding::new(
                        "test fixture assigns a real-looking secret to a credential-named variable; use an obviously-fake placeholder instead",
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
        SecretInTestFixtureRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_real_looking_secret_in_ts_spec_file() {
        let code = "const apiToken = \"aG3n7Zq9Lm2XpW5vBt8FhKc1RdSy\";\n";
        assert_eq!(
            check(
                "src/auth.spec.ts",
                LanguageIdentifier::typescript(),
                code
            )
            .len(),
            1
        );
    }

    #[test]
    fn flags_real_looking_secret_in_python_test_fixture() {
        let code = "password = \"Xk9pQz2mWv7RtYc4Ln8B\"\n";
        assert_eq!(
            check("tests/fixtures/user.py", LanguageIdentifier::python(), code).len(),
            1
        );
    }

    #[test]
    fn ignores_placeholder_secret_in_test_file() {
        let code = "const apiToken = \"YOUR_API_KEY\";\n";
        assert!(
            check("src/auth.test.ts", LanguageIdentifier::typescript(), code).is_empty()
        );
    }

    #[test]
    fn ignores_real_looking_secret_outside_test_paths() {
        let code = "const apiToken = \"aG3n7Zq9Lm2XpW5vBt8FhKc1RdSy\";\n";
        assert!(
            check("src/auth.ts", LanguageIdentifier::typescript(), code).is_empty()
        );
    }

    #[test]
    fn recognizes_mocks_and_fixtures_directories() {
        let code = "secret_key = \"Xk9pQz2mWv7RtYc4Ln8B\"\n";
        assert_eq!(
            check(
                "__fixtures__/config.py",
                LanguageIdentifier::python(),
                code
            )
            .len(),
            1
        );
        assert_eq!(
            check("__mocks__/config.py", LanguageIdentifier::python(), code).len(),
            1
        );
    }
}
