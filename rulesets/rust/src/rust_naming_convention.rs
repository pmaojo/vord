use vord_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use vord_rules_engine::{declare_rule_id, Finding, IssueType, Rule, RuleId, Severity};

declare_rule_id!(RustNamingConventionRule, "naming:rust-convention");

impl Rule for RustNamingConventionRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn applies_to(&self, language: &LanguageIdentifier) -> bool {
        *language == LanguageIdentifier::rust()
    }

    fn default_severity(&self) -> Severity {
        Severity::Minor
    }

    fn issue_type(&self) -> IssueType {
        IssueType::CodeSmell
    }

    fn check(&self, _file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        let mut findings = Vec::new();

        fn walk(node: &AstNode, out: &mut Vec<Finding>) {
            let kind_str = match node.kind() {
                NodeKind::Other(k) => k.as_ref().to_string(),
                _ => String::new(),
            };

            if kind_str == "struct_item" || kind_str == "enum_item" || kind_str == "trait_item" {
                if let Some(name_node) = node.children().iter().find(|c| *c.kind() == NodeKind::Identifier || matches!(c.kind(), NodeKind::Other(k) if k.as_ref() == "type_identifier")) {
                    let name = name_node.text();
                    if !is_pascal_case(name) {
                        out.push(Finding::new(
                            format!("Rust type `{}` should use `PascalCase`.", name),
                            name_node.span(),
                        ));
                    }
                }
            } else if kind_str == "function_item" {
                if let Some(name_node) = node.children().iter().find(|c| *c.kind() == NodeKind::Identifier) {
                    let name = name_node.text();
                    if !is_snake_case(name) && !name.starts_with("test_") {
                        out.push(Finding::new(
                            format!("Rust function `{}` should use `snake_case`.", name),
                            name_node.span(),
                        ));
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

fn is_pascal_case(s: &str) -> bool {
    let mut chars = s.chars();
    match chars.next() {
        Some(c) if c.is_uppercase() => !s.contains('_'),
        _ => false,
    }
}

fn is_snake_case(s: &str) -> bool {
    s.chars().all(|c| c.is_lowercase() || c.is_numeric() || c == '_')
}
