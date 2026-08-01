use yunq_ast::{AstNode, LanguageIdentifier, SourceFile};
use yunq_rules_engine::{declare_rule_id, Finding, IssueType, Rule, RuleId, Severity};

declare_rule_id!(NoSqlInjectionRule, "owasp:nosql-injection");

impl Rule for NoSqlInjectionRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn applies_to(&self, language: &LanguageIdentifier) -> bool {
        language.is_typescript() || language.is_javascript() || language.is_python()
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
            if (text.contains("$where") || text.contains("$gt") || text.contains("$ne") || text.contains("$regex"))
                && (text.contains("req.body") || text.contains("req.query") || text.contains("request.args") || text.contains("request.json"))
            {
                out.push(Finding::new(
                    "Potential NoSQL Injection: Unsanitized HTTP request input passed directly into MongoDB query operator ($where/$gt/$ne/$regex). Sanitize or cast query parameters explicitly.",
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
