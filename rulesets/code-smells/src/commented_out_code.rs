//! Rule: flags comments whose content looks like commented-out code rather
//! than prose documentation.

use yunq_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use yunq_rules_engine::{Finding, Rule, RuleId, Severity};

const CODE_KEYWORDS: &[&str] = &[
    "if ",
    "if(",
    "for ",
    "for(",
    "while ",
    "while(",
    "function ",
    "function(",
    "def ",
    "class ",
    "return ",
    "const ",
    "let ",
    "var ",
    "public ",
    "private ",
    "import ",
    "from ",
];

/// Strips common comment markers (`//`, `#`, `/* ... */`, leading `*`) from a
/// single line, returning the inner text trimmed of whitespace.
fn strip_comment_markers(text: &str) -> String {
    let mut s = text.trim();
    for prefix in ["///", "//!", "//", "#", "/**", "/*", "*"] {
        if let Some(rest) = s.strip_prefix(prefix) {
            s = rest.trim();
            break;
        }
    }
    s.strip_suffix("*/").unwrap_or(s).trim().to_string()
}

fn looks_like_code(inner: &str) -> bool {
    if inner.is_empty() || inner.ends_with('.') || inner.ends_with('?') || inner.ends_with('!') {
        return false;
    }
    let starts_with_keyword = CODE_KEYWORDS.iter().any(|kw| inner.starts_with(kw));
    let has_code_punctuation = inner.ends_with(';')
        || inner.ends_with('{')
        || inner.ends_with(')')
        || inner.contains(" = ");
    starts_with_keyword && has_code_punctuation
}

pub struct CommentedOutCodeRule {
    id: RuleId,
}

impl CommentedOutCodeRule {
    pub fn new() -> Self {
        Self {
            id: RuleId::new("smells:commented-out-code").expect("valid rule id"),
        }
    }
}

impl Default for CommentedOutCodeRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for CommentedOutCodeRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn applies_to(&self, _language: &LanguageIdentifier) -> bool {
        true
    }

    fn default_severity(&self) -> Severity {
        Severity::Minor
    }

    fn check(&self, _file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        ast.descendants()
            .filter(|n| *n.kind() == NodeKind::Comment)
            .filter_map(|comment| {
                let inner = strip_comment_markers(comment.text());
                looks_like_code(&inner).then(|| {
                    Finding::new(
                        format!("comment looks like commented-out code: `{inner}`"),
                        comment.span(),
                    )
                })
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn comment(text: &str) -> AstNode {
        AstNode::new(
            NodeKind::Comment,
            yunq_ast::Span::new(1, 1, 1, text.len() as u32),
            text,
            vec![],
        )
    }

    #[test]
    fn flags_commented_out_statement() {
        let ast = comment("// const total = price * quantity;");
        let findings = CommentedOutCodeRule::new().check(
            &SourceFile::new("t.ts", "", LanguageIdentifier::typescript()).unwrap(),
            &ast,
        );
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn allows_prose_comment() {
        let ast = comment("// This computes the total price for the order.");
        let findings = CommentedOutCodeRule::new().check(
            &SourceFile::new("t.ts", "", LanguageIdentifier::typescript()).unwrap(),
            &ast,
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn allows_short_marker_comment() {
        let ast = comment("// TODO");
        let findings = CommentedOutCodeRule::new().check(
            &SourceFile::new("t.ts", "", LanguageIdentifier::typescript()).unwrap(),
            &ast,
        );
        assert!(findings.is_empty());
    }
}
