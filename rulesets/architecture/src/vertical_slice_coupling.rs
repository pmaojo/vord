//! Rule: `architecture:cross-slice-coupling`
//! Enforces Vertical Slice Architecture purity: independent slices/features
//! must not directly depend on private internal details of another slice.
//! Interactions between slices must occur via Domain Events or explicit public contracts.

use yunq_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use yunq_rules_engine::{Finding, IssueType, Rule, RuleId, Severity, declare_rule_id};

declare_rule_id!(VerticalSliceCouplingRule, "architecture:cross-slice-coupling");

impl Rule for VerticalSliceCouplingRule {
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
        let mut findings = Vec::new();
        let path = file.path();

        // Check if file is in a vertical slice directory: e.g. "features/orders/..." or "slices/billing/..."
        if !path.contains("features/") && !path.contains("slices/") {
            return findings;
        }

        fn walk(node: &AstNode, _file_path: &str, out: &mut Vec<Finding>) {
            let is_import = matches!(node.kind(), NodeKind::Other(k) if k.as_ref() == "import_statement" || k.as_ref() == "use_declaration");

            if is_import {
                let text = node.text();
                // Flag deep imports across feature boundaries: e.g. "features/billing/internal/..."
                if (text.contains("features/") || text.contains("slices/")) && text.contains("/internal/") {
                    out.push(Finding::new(
                        format!(
                            "Vertical Slice Boundary Breach: `{}` directly imports private internal details from another slice. Slices must be autonomous — communicate via Domain Events or public contracts.",
                            text.trim()
                        ),
                        node.span(),
                    ));
                }
            }

            for child in node.children() {
                walk(child, _file_path, out);
            }
        }

        for child in ast.children() {
            walk(child, path, &mut findings);
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
    fn test_flags_cross_slice_internal_import() {
        let code = r#"
        import { BillingInternalHandler } from '../slices/billing/internal/handler';
        "#;
        let file = SourceFile::new("features/orders/handler.ts", code, LanguageIdentifier::typescript()).unwrap();
        let ast = TypeScriptParser::new().parse(&file).unwrap();
        let findings = VerticalSliceCouplingRule::new().check(&file, &ast);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("Vertical Slice Boundary Breach"));
    }
}
