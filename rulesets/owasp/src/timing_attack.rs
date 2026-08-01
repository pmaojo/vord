use yunq_ast::{AstNode, LanguageIdentifier, SourceFile};
use yunq_rules_engine::{declare_rule_id, Finding, IssueType, Rule, RuleId, Severity};

declare_rule_id!(TimingAttackRule, "owasp:timing-attack-comparison");

impl Rule for TimingAttackRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn applies_to(&self, language: &LanguageIdentifier) -> bool {
        language.is_typescript() || language.is_javascript() || language.is_python() || language.is_rust()
    }

    fn default_severity(&self) -> Severity {
        Severity::Major
    }

    fn issue_type(&self) -> IssueType {
        IssueType::Vulnerability
    }

    fn check(&self, _file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        let mut findings = Vec::new();

        fn walk(node: &AstNode, out: &mut Vec<Finding>) {
            let text = node.text();
            if (text.contains("token") || text.contains("apiKey") || text.contains("api_key") || text.contains("secret") || text.contains("hash") || text.contains("signature"))
                && (text.contains("==") || text.contains("==="))
                && !text.contains("timingSafeEqual")
                && !text.contains("constant_time")
            {
                out.push(Finding::new(
                    "Potential Timing Attack vulnerability: Direct equality (`==`/`===`) used to compare secret token/signature/hash. Use constant-time string comparison (`crypto.timingSafeEqual`, `hmac.compare_digest`).",
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
