//! Flags a real `.env` file (as opposed to a safe template/example variant)
//! being committed to the repository at all — regardless of its contents.
//! `.env` files routinely hold live credentials pulled in at runtime, so the
//! mere presence of one in version control is the risk, not any particular
//! line inside it.

use vord_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile, Span};
use vord_rules_engine::{Finding, IssueType, Rule, RuleId, RuleMetadata, Severity};

/// Filename suffixes that mark a `.env` file as a safe template rather than
/// a real, potentially secret-bearing environment file.
const SAFE_TEMPLATE_SUFFIXES: &[&str] = &[
    ".example",
    ".sample",
    ".template",
    ".dist",
];

/// Returns true when `filename` (the final path segment, e.g. `.env.production`)
/// is a real `.env` file rather than a safe template variant.
fn is_real_dotenv_filename(filename: &str) -> bool {
    if filename == ".env" {
        return true;
    }
    if !filename.starts_with(".env.") {
        return false;
    }
    let lower = filename.to_lowercase();
    !SAFE_TEMPLATE_SUFFIXES
        .iter()
        .any(|suffix| lower.ends_with(suffix))
}

pub struct DotenvFileCommittedRule {
    id: RuleId,
}

impl DotenvFileCommittedRule {
    pub fn new() -> Self {
        Self {
            id: RuleId::new("secrets:dotenv-file-committed").expect("valid rule id"),
        }
    }
}

impl Default for DotenvFileCommittedRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for DotenvFileCommittedRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn applies_to(&self, _language: &LanguageIdentifier) -> bool {
        true
    }

    fn default_severity(&self) -> Severity {
        Severity::Major
    }

    fn issue_type(&self) -> IssueType {
        IssueType::Vulnerability
    }

    fn metadata(&self) -> RuleMetadata {
        RuleMetadata {
            description: "A real `.env` file (not a `.example`/`.sample`/`.template`/`.dist` placeholder) is committed to the repository. `.env` files typically hold live credentials and should never be checked in.".into(),
            tags: vec!["security".into(), "secrets".into(), "owasp-a07".into()],
            cwe: Some(798),
            produces_hotspots: false,
        }
    }

    fn check(&self, file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        if *ast.kind() != NodeKind::SourceUnit {
            return Vec::new();
        }

        let path = file.path();
        let filename = path.rsplit(['/', '\\']).next().unwrap_or(path);

        if !is_real_dotenv_filename(filename) {
            return Vec::new();
        }

        vec![Finding::new(
            format!(
                "'{filename}' is a real .env file committed to the repository; it likely contains live credentials — use a `.example`/`.sample`/`.template` placeholder instead and keep the real file untracked"
            ),
            Span::new(1, 1, 1, 1),
        )]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check(path: &str, content: &str) -> Vec<Finding> {
        let file = SourceFile::new(path, content, LanguageIdentifier::bash()).unwrap();
        let ast = AstNode::new(
            NodeKind::SourceUnit,
            Span::new(1, 1, 1, content.len().max(1) as u32),
            content,
            vec![],
        );
        DotenvFileCommittedRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_plain_dotenv() {
        let findings = check(".env", "SECRET=abc123\n");
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn flags_environment_specific_dotenv() {
        assert_eq!(check(".env.production", "SECRET=abc123\n").len(), 1);
        assert_eq!(check(".env.local", "SECRET=abc123\n").len(), 1);
        assert_eq!(
            check("config/.env.staging", "SECRET=abc123\n").len(),
            1
        );
    }

    #[test]
    fn ignores_safe_template_variants() {
        for name in [".env.example", ".env.sample", ".env.template", ".env.dist"] {
            assert!(
                check(name, "SECRET=abc123\n").is_empty(),
                "flagged safe template {name}"
            );
        }
    }

    #[test]
    fn ignores_unrelated_files() {
        assert!(check("environment.ts", "const x = 1;\n").is_empty());
        assert!(check("main.py", "x = 1\n").is_empty());
    }
}
