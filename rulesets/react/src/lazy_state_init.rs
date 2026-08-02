//! Rule: Warns when function calls are passed directly to `useState` instead of a lazy initializer `useState(() => ...)` to avoid expensive re-evaluation on every render.

use vord_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use vord_rules_engine::{Finding, IssueType, Rule, RuleId, RuleMetadata, Severity};

pub struct LazyStateInitRule {
    id: RuleId,
}

impl LazyStateInitRule {
    pub fn new() -> Self {
        Self {
            id: RuleId::new("react:lazy-state-init").expect("valid rule id"),
        }
    }
}

impl Default for LazyStateInitRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for LazyStateInitRule {
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
            description: "Pass a function initializer `useState(() => expensiveCalculation())` instead of invoking the function directly in `useState(...)` to prevent re-running expensive calculations on every render.".into(),
            tags: vec!["react".into(), "performance".into(), "rerender".into()],
            cwe: None,
            produces_hotspots: false,
        }
    }

    fn check(&self, _file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        let mut findings = Vec::new();

        for node in ast.descendants() {
            if *node.kind() == NodeKind::Call {
                let callee_text = node.children().first().map(|n| n.text()).unwrap_or("");
                if callee_text == "useState" || callee_text.ends_with(".useState") {
                    let children = node.children();
                    if children.len() > 1 {
                        let arg = &children[1];
                        if *arg.kind() == NodeKind::Call {
                            findings.push(Finding::new(
                                format!("Function call `{}` in `useState` is evaluated on every render. Use lazy initialization `useState(() => ...)` instead.", arg.text()),
                                arg.span(),
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
    fn flags_eager_function_call_in_use_state() {
        let rule = LazyStateInitRule::new();
        let file = SourceFile::new(
            "App.tsx",
            "const [data, setData] = useState(computeInitialData());",
            LanguageIdentifier::typescript(),
        )
        .unwrap();

        let callee = AstNode::new(
            NodeKind::Identifier,
            Span::new(1, 26, 1, 34),
            "useState",
            vec![],
        );
        let inner_fn = AstNode::new(
            NodeKind::Identifier,
            Span::new(1, 35, 1, 53),
            "computeInitialData",
            vec![],
        );
        let arg_call = AstNode::new(
            NodeKind::Call,
            Span::new(1, 35, 1, 55),
            "computeInitialData()",
            vec![inner_fn],
        );
        let use_state_call = AstNode::new(
            NodeKind::Call,
            Span::new(1, 26, 1, 56),
            "useState(computeInitialData())",
            vec![callee, arg_call],
        );

        let findings = rule.check(&file, &use_state_call);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("lazy initialization"));
    }

    #[test]
    fn allows_literal_or_lazy_init() {
        let rule = LazyStateInitRule::new();
        let file = SourceFile::new(
            "App.tsx",
            "const [count, setCount] = useState(0);",
            LanguageIdentifier::typescript(),
        )
        .unwrap();

        let callee = AstNode::new(
            NodeKind::Identifier,
            Span::new(1, 27, 1, 35),
            "useState",
            vec![],
        );
        let arg_literal = AstNode::new(
            NodeKind::StringLiteral,
            Span::new(1, 36, 1, 37),
            "0",
            vec![],
        );
        let use_state_call = AstNode::new(
            NodeKind::Call,
            Span::new(1, 27, 1, 38),
            "useState(0)",
            vec![callee, arg_literal],
        );

        let findings = rule.check(&file, &use_state_call);
        assert!(findings.is_empty());
    }
}
