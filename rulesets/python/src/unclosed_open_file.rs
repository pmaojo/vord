use vord_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use vord_rules_engine::{declare_rule_id, Finding, IssueType, Rule, RuleId, Severity};

declare_rule_id!(UnclosedOpenFileRule, "python:unclosed-open-file");

impl Rule for UnclosedOpenFileRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn applies_to(&self, language: &LanguageIdentifier) -> bool {
        *language == LanguageIdentifier::python()
    }

    fn default_severity(&self) -> Severity {
        Severity::Major
    }

    fn issue_type(&self) -> IssueType {
        IssueType::CodeSmell
    }

    fn check(&self, _file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        let mut findings = Vec::new();

        fn walk<'a>(node: &'a AstNode, out: &mut Vec<Finding>) {
            let kind_str = match node.kind() {
                NodeKind::Other(k) => k.as_ref().to_string(),
                _ => String::new(),
            };

            // Call to `open()` without `with` statement parent
            if kind_str == "call" {
                if let Some(fn_node) = node.first_child() {
                    if fn_node.text() == "open" {
                        let text = node.text();
                        if !text.contains("with open") {
                            out.push(Finding::new(
                                "File opened with `open()` outside a `with` context manager. Use `with open(...) as f:` to prevent unclosed file descriptor leaks.",
                                node.span(),
                            ));
                        }
                    }
                }
            }

            for child in node.children() {
                walk(child, out);
            }
        }

        walk(ast, &mut findings);
        findings
    }
}
