use yunq_ast::{AstNode, LanguageIdentifier, SourceFile};
use yunq_rules_engine::{declare_rule_id, Finding, IssueType, Rule, RuleId, Severity};

declare_rule_id!(FolderNamingCasingRule, "architecture:folder-naming-casing");

impl Rule for FolderNamingCasingRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn applies_to(&self, _language: &LanguageIdentifier) -> bool {
        true
    }

    fn default_severity(&self) -> Severity {
        Severity::Major
    }

    fn issue_type(&self) -> IssueType {
        IssueType::CodeSmell
    }

    fn check(&self, file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        let path = file.path();
        let parts: Vec<&str> = path.split(['/', '\\']).collect();
        // Ignore file itself (last part), check directory names
        for &dir in parts.iter().take(parts.len().saturating_sub(1)) {
            if dir == "." || dir == "src" || dir == "node_modules" || dir == "target" || dir.starts_with('.') {
                continue;
            }
            if dir.chars().any(|c| c.is_uppercase()) && dir.contains('_') {
                return vec![Finding::new(
                    format!("Directory `{}` uses mixed casing convention. Enforce consistent `kebab-case` or `snake_case` directory naming.", dir),
                    ast.span(),
                )];
            }
        }
        Vec::new()
    }
}
