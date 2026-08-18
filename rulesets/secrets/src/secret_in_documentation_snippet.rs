//! Flags a real-looking secret inside a fenced code block (` ``` `) in a
//! Markdown/MDX file. Documentation snippets are meant to demonstrate usage
//! with placeholder values ("replace this with your own key"); a real
//! credential pasted into a README or guide is both highly visible and
//! easy to overlook during review.

use vord_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile, Span};
use vord_rules_engine::{Finding, IssueType, Rule, RuleId, RuleMetadata, Severity};

use crate::secret_literal::{CREDENTIAL_ASSIGNMENT, assignment_value, looks_like_real_secret};

fn is_markdown_path(path: &str) -> bool {
    let lower = path.to_lowercase();
    lower.ends_with(".md") || lower.ends_with(".mdx")
}

pub struct SecretInDocumentationSnippetRule {
    id: RuleId,
}

impl SecretInDocumentationSnippetRule {
    pub fn new() -> Self {
        Self {
            id: RuleId::new("secrets:secret-in-documentation-snippet").expect("valid rule id"),
        }
    }
}

impl Default for SecretInDocumentationSnippetRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for SecretInDocumentationSnippetRule {
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
            description: "A fenced code block in a Markdown/MDX documentation file contains a real-looking credential rather than a placeholder. Documentation snippets are widely read and easy to forget when rotating leaked secrets.".into(),
            tags: vec!["security".into(), "secrets".into(), "owasp-a07".into()],
            cwe: Some(798),
            produces_hotspots: false,
        }
    }

    fn check(&self, file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        if *ast.kind() != NodeKind::SourceUnit {
            return Vec::new();
        }
        if !is_markdown_path(file.path()) {
            return Vec::new();
        }

        let mut findings = Vec::new();
        let mut in_fence = false;
        for (idx, line) in file.content().lines().enumerate() {
            if line.trim_start().starts_with("```") {
                in_fence = !in_fence;
                continue;
            }
            if !in_fence {
                continue;
            }

            for caps in CREDENTIAL_ASSIGNMENT.captures_iter(line) {
                let value = assignment_value(&caps);
                if looks_like_real_secret(value) {
                    let line_no = (idx + 1) as u32;
                    findings.push(Finding::new(
                        "documentation code snippet contains a real-looking credential; replace it with an obviously-fake placeholder value",
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

    fn check(path: &str, code: &str) -> Vec<Finding> {
        let file = SourceFile::new(path, code, LanguageIdentifier::html()).unwrap();
        let ast = AstNode::new(
            NodeKind::SourceUnit,
            Span::new(1, 1, 1, code.len().max(1) as u32),
            code,
            vec![],
        );
        SecretInDocumentationSnippetRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_real_secret_in_fenced_block_in_md() {
        let code = "# Setup\n\n```bash\nexport API_TOKEN=aG3n7Zq9Lm2XpW5vBt8FhKc1RdSy\n```\n";
        assert_eq!(check("README.md", code).len(), 1);
    }

    #[test]
    fn flags_real_secret_in_fenced_block_in_mdx() {
        let code = "```js\nconst apiKey = \"Xk9pQz2mWv7RtYc4Ln8B\";\n```\n";
        assert_eq!(check("guide.mdx", code).len(), 1);
    }

    #[test]
    fn ignores_placeholder_in_fenced_block() {
        let code = "```bash\nexport API_TOKEN=YOUR_API_KEY\n```\n";
        assert!(check("README.md", code).is_empty());
    }

    #[test]
    fn ignores_secret_outside_fenced_block() {
        let code = "The token `API_TOKEN=aG3n7Zq9Lm2XpW5vBt8FhKc1RdSy` is just prose here.\n";
        // Outside a fenced block, so not treated as a documentation snippet.
        assert!(check("README.md", code).is_empty());
    }

    #[test]
    fn ignores_non_markdown_files() {
        let code = "```bash\nexport API_TOKEN=aG3n7Zq9Lm2XpW5vBt8FhKc1RdSy\n```\n";
        assert!(check("notes.txt", code).is_empty());
    }
}
