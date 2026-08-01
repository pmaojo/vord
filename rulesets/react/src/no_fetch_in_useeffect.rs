use yunq_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use yunq_rules_engine::{declare_rule_id, Finding, IssueType, Rule, RuleId, Severity};

declare_rule_id!(NoFetchInUseEffectRule, "react:no-fetch-in-useeffect");

impl Rule for NoFetchInUseEffectRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn applies_to(&self, language: &LanguageIdentifier) -> bool {
        language.is_typescript() || language.is_javascript()
    }

    fn default_severity(&self) -> Severity {
        Severity::Major
    }

    fn issue_type(&self) -> IssueType {
        IssueType::CodeSmell
    }

    fn check(&self, _file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        let mut findings = Vec::new();

        fn check_call<'a>(node: &'a AstNode, out: &mut Vec<Finding>) {
            if matches!(node.kind(), NodeKind::Other(k) if k.as_ref() == "call_expression") {
                if let Some(fn_node) = node.first_child() {
                    if fn_node.text() == "useEffect" || fn_node.text() == "React.useEffect" {
                        // Inspect the callback body for fetch or axios
                        let text = node.text();
                        if text.contains("fetch(") || text.contains("axios.") || text.contains("axios(") {
                            out.push(Finding::new(
                                "Avoid data fetching (`fetch`/`axios`) directly inside `useEffect`. Use a dedicated data fetching library (TanStack Query, SWR) or custom hooks to handle caching, race conditions, and error states.",
                                node.span(),
                            ));
                        }
                    }
                }
            }
            for child in node.children() {
                check_call(child, out);
            }
        }

        check_call(ast, &mut findings);
        findings
    }
}
