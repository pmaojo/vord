//! Rule: `ddd:repository-per-entity`
//! Enforces the core DDD rule: Repositories exist ONLY for Aggregate Roots,
//! never for individual child entities. Accessing child entities directly via
//! a repository breaches the aggregate boundary and consistency guarantee.

use yunq_ast::{AstNode, LanguageIdentifier, SourceFile};
use yunq_rules_engine::{Finding, IssueType, Rule, RuleId, Severity, declare_rule_id};

declare_rule_id!(RepositoryPerEntityRule, "ddd:repository-per-entity");

impl Rule for RepositoryPerEntityRule {
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

    fn check(&self, _file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        let mut findings = Vec::new();

        fn walk(node: &AstNode, out: &mut Vec<Finding>) {
            let text = node.text();
            
            // Detect repositories named after known child entity concepts instead of Aggregate Roots
            if text.contains("Repository")
                && (text.contains("ItemRepository")
                    || text.contains("DetailRepository")
                    || text.contains("LineRepository")
                    || text.contains("ChildRepository"))
            {
                out.push(Finding::new(
                    format!(
                        "DDD Boundary Breach: Repository `{}` declared for a child entity. Repositories must exist ONLY for Aggregate Roots (e.g. OrderRepository), loading and persisting child entities through the Aggregate Root.",
                        text.trim()
                    ),
                    node.span(),
                ));
            }

            for child in node.children() {
                walk(child, out);
            }
        }

        for child in ast.children() {
            walk(child, &mut findings);
        }

        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use yunq_parser_typescript::TypeScriptParser;
    use yunq_rules_engine::AstParser;

    #[test]
    fn test_flags_child_entity_repository() {
        let code = r#"
        interface OrderItemRepository {
            save(item: OrderItem): void;
        }
        "#;
        let file = SourceFile::new("src/order.ts", code, LanguageIdentifier::typescript()).unwrap();
        let ast = TypeScriptParser::new().parse(&file).unwrap();
        let findings = RepositoryPerEntityRule::new().check(&file, &ast);
        assert!(!findings.is_empty());
        assert!(findings[0].message.contains("DDD Boundary Breach"));
    }
}
