use vord_ast::{AstNode, LanguageIdentifier, SourceFile};
use vord_rules_engine::{declare_rule_id, Finding, IssueType, Rule, RuleId, Severity};

declare_rule_id!(DatetimeUtcnowDeprecatedRule, "python:datetime-utcnow-deprecated");

impl Rule for DatetimeUtcnowDeprecatedRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn applies_to(&self, language: &LanguageIdentifier) -> bool {
        *language == LanguageIdentifier::python()
    }

    fn default_severity(&self) -> Severity {
        Severity::Minor
    }

    fn issue_type(&self) -> IssueType {
        IssueType::CodeSmell
    }

    fn check(&self, _file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        let mut findings = Vec::new();

        fn walk<'a>(node: &'a AstNode, out: &mut Vec<Finding>) {
            let text = node.text();
            if text.contains("datetime.utcnow()") || text.contains("datetime.utcfromtimestamp(") {
                out.push(Finding::new(
                    "`datetime.utcnow()` is deprecated in Python 3.12+. Use timezone-aware `datetime.now(datetime.timezone.utc)` instead.",
                    node.span(),
                ));
            }
            for child in node.children() {
                walk(child, out);
            }
        }

        walk(ast, &mut findings);
        findings
    }
}
