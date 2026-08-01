use yunq_ast::{AstNode, LanguageIdentifier, SourceFile};
use yunq_rules_engine::{declare_rule_id, Finding, IssueType, Rule, RuleId, Severity};

declare_rule_id!(PrototypePollutionRule, "owasp:prototype-pollution");

impl Rule for PrototypePollutionRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn applies_to(&self, language: &LanguageIdentifier) -> bool {
        language.is_typescript() || language.is_javascript()
    }

    fn default_severity(&self) -> Severity {
        Severity::Critical
    }

    fn issue_type(&self) -> IssueType {
        IssueType::Vulnerability
    }

    fn check(&self, _file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        let mut findings = Vec::new();

        fn walk(node: &AstNode, out: &mut Vec<Finding>) {
            let text = node.text();
            if (text.contains("__proto__") || text.contains("constructor.prototype"))
                && (text.contains("Object.assign") || text.contains("merge(") || text.contains("extend(") || text.contains("deepMerge"))
            {
                out.push(Finding::new(
                    "Potential Prototype Pollution vulnerability: Merging or copying properties via `__proto__` or `constructor.prototype`. Freeze or validate object keys prior to deep operations.",
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
