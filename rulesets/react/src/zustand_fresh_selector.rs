//! Rule: Flags Zustand store selectors that return a fresh object/array literal on every render without `useShallow`.

use vord_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use vord_rules_engine::{Finding, IssueType, Rule, RuleId, RuleMetadata, Severity};

pub struct ZustandFreshSelectorRule {
    id: RuleId,
}

impl ZustandFreshSelectorRule {
    pub fn new() -> Self {
        Self {
            id: RuleId::new("react:zustand-fresh-selector").expect("valid rule id"),
        }
    }
}

impl Default for ZustandFreshSelectorRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for ZustandFreshSelectorRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn applies_to(&self, lang: &LanguageIdentifier) -> bool {
        *lang == LanguageIdentifier::typescript()
    }

    fn default_severity(&self) -> Severity {
        Severity::Major
    }

    fn issue_type(&self) -> IssueType {
        IssueType::CodeSmell
    }

    fn metadata(&self) -> RuleMetadata {
        RuleMetadata {
            description: "Zustand selector returns a new object or array reference on every render, triggering unnecessary re-renders. Wrap selector with `useShallow` or select individual primitive fields.".into(),
            tags: vec!["react".into(), "zustand".into(), "performance".into(), "rerender".into()],
            cwe: None,
            produces_hotspots: false,
        }
    }

    fn check(&self, _file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        let mut findings = Vec::new();

        for node in ast.descendants() {
            if *node.kind() == NodeKind::Call {
                let callee_text = node.children().first().map(|n| n.text()).unwrap_or("");
                if callee_text.starts_with("use") && callee_text.ends_with("Store") {
                    let children = node.children();
                    if children.len() > 1 {
                        let selector_arg = &children[1];
                        let arg_text = selector_arg.text();
                        if (arg_text.contains("=> ({") || arg_text.contains("=> ["))
                            && !node.text().contains("useShallow")
                        {
                            findings.push(Finding::new(
                                format!("Zustand selector `{callee_text}` creates a fresh object/array reference on every render. Wrap with `useShallow` to avoid unnecessary re-renders."),
                                selector_arg.span(),
                            ));
                        }
                    }
                }
            }
        }

        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vord_ast::Span;

    #[test]
    fn flags_fresh_object_selector_in_zustand() {
        let rule = ZustandFreshSelectorRule::new();
        let file = SourceFile::new(
            "App.tsx",
            "const { a, b } = useUserStore(state => ({ a: state.a, b: state.b }));",
            LanguageIdentifier::typescript(),
        )
        .unwrap();

        let callee = AstNode::new(
            NodeKind::Identifier,
            Span::new(1, 18, 1, 30),
            "useUserStore",
            vec![],
        );
        let selector = AstNode::new(
            NodeKind::Call,
            Span::new(1, 31, 1, 69),
            "state => ({ a: state.a, b: state.b })",
            vec![],
        );
        let call = AstNode::new(
            NodeKind::Call,
            Span::new(1, 18, 1, 70),
            "useUserStore(state => ({ a: state.a, b: state.b }))",
            vec![callee, selector],
        );

        let findings = rule.check(&file, &call);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("useShallow"));
    }

    #[test]
    fn allows_primitive_selector() {
        let rule = ZustandFreshSelectorRule::new();
        let file = SourceFile::new(
            "App.tsx",
            "const a = useUserStore(state => state.a);",
            LanguageIdentifier::typescript(),
        )
        .unwrap();

        let callee = AstNode::new(
            NodeKind::Identifier,
            Span::new(1, 10, 1, 22),
            "useUserStore",
            vec![],
        );
        let selector = AstNode::new(
            NodeKind::Call,
            Span::new(1, 23, 1, 39),
            "state => state.a",
            vec![],
        );
        let call = AstNode::new(
            NodeKind::Call,
            Span::new(1, 10, 1, 40),
            "useUserStore(state => state.a)",
            vec![callee, selector],
        );

        let findings = rule.check(&file, &call);
        assert!(findings.is_empty());
    }
}
