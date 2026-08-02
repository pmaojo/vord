use vord_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use vord_rules_engine::{Finding, Rule, RuleId, Severity};

/// Tracks postponed-work comment markers so they stay visible.
pub struct TodoCommentRule {
    id: RuleId,
}

impl TodoCommentRule {
    pub fn new() -> Self {
        Self { id: RuleId::new("smells:todo-comment").expect("valid rule id") }
    }
}

impl Default for TodoCommentRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for TodoCommentRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn applies_to(&self, _language: &LanguageIdentifier) -> bool {
        true
    }

    fn default_severity(&self) -> Severity {
        Severity::Info
    }

    fn check(&self, _file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        ast.descendants()
            .filter(|n| *n.kind() == NodeKind::Comment)
            .filter_map(|comment| {
                let marker = ["TODO", "FIXME"].into_iter().find(|m| comment.text().contains(m))?;
                Some(Finding::new(format!("unresolved {marker} comment"), comment.span()))
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use vord_ast::SourceFile;
    use vord_rules_engine::AstParser;

    use super::*;

    #[test]
    fn flags_todo_and_fixme_in_rust() {
        let file = SourceFile::new(
            "t.rs",
            "// TODO: refactor\nfn a() {}\n/* FIXME: broken */\nfn b() {}\n// plain note\n",
            LanguageIdentifier::rust(),
        )
        .unwrap();
        let ast = vord_parser_rust::RustParser::new().parse(&file).unwrap();
        let findings = TodoCommentRule::new().check(&file, &ast);
        assert_eq!(findings.len(), 2);
    }
}
