//! Rule: an interface/trait with too many method members — the Interface
//! Segregation smell: implementers are forced to depend on (and stub out)
//! methods they don't actually need just to satisfy one fat contract, when
//! several narrower role interfaces would let each implementer depend on
//! only what it uses. Per-file (`Rule`, not `CrossFileRule`): an
//! interface/trait's own member count needs nothing beyond its own
//! declaration.

use yunq_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use yunq_rules_engine::{Finding, Rule, RuleId, RuleMetadata, Severity};

fn is_other(node: &AstNode, kind: &str) -> bool {
    matches!(node.kind(), NodeKind::Other(k) if k.as_ref() == kind)
}

/// TS `interface_declaration`s: (node, name, method-signature count). Only
/// `method_signature` members count — `property_signature` (plain data
/// fields) aren't behavior a segregated interface needs to split apart.
fn ts_interfaces(ast: &AstNode) -> Vec<(&AstNode, String, usize)> {
    ast.descendants()
        .filter(|n| is_other(n, "interface_declaration"))
        .filter_map(|node| {
            let name = node.children().iter().find(|c| is_other(c, "type_identifier"))?.text().to_string();
            let body = node.children().iter().find(|c| is_other(c, "interface_body"))?;
            let method_count = body.children().iter().filter(|c| is_other(c, "method_signature")).count();
            Some((node, name, method_count))
        })
        .collect()
}

/// Rust `trait_item`s: (node, name, method count) — both signature-only
/// (`function_signature_item`) and default-bodied (`FunctionDef`) methods
/// count toward the contract implementers must satisfy.
fn rust_traits(ast: &AstNode) -> Vec<(&AstNode, String, usize)> {
    ast.descendants()
        .filter(|n| is_other(n, "trait_item"))
        .filter_map(|node| {
            let name = node.children().iter().find(|c| is_other(c, "type_identifier"))?.text().to_string();
            let body = node.children().iter().find(|c| is_other(c, "declaration_list"))?;
            let method_count = body
                .children()
                .iter()
                .filter(|c| is_other(c, "function_signature_item") || *c.kind() == NodeKind::FunctionDef)
                .count();
            Some((node, name, method_count))
        })
        .collect()
}

pub struct FatInterfaceRule {
    id: RuleId,
    max_methods: usize,
}

impl FatInterfaceRule {
    pub fn new(max_methods: usize) -> Self {
        Self { id: RuleId::new("smells:fat-interface").expect("valid rule id"), max_methods }
    }
}

impl Default for FatInterfaceRule {
    fn default() -> Self {
        Self::new(8)
    }
}

impl Rule for FatInterfaceRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn applies_to(&self, language: &LanguageIdentifier) -> bool {
        *language == LanguageIdentifier::typescript() || *language == LanguageIdentifier::rust()
    }

    fn default_severity(&self) -> Severity {
        Severity::Minor
    }

    fn metadata(&self) -> RuleMetadata {
        RuleMetadata {
            description: "An interface/trait declares more methods than a single role needs, forcing every implementer to depend on (and often stub) methods it doesn't use — split it into smaller, role-specific interfaces.".into(),
            tags: vec!["design".into(), "interface-segregation".into()],
            cwe: None,
            produces_hotspots: false,
        }
    }

    fn check(&self, _file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        ts_interfaces(ast)
            .into_iter()
            .chain(rust_traits(ast))
            .filter(|(_, _, count)| *count > self.max_methods)
            .map(|(node, name, count)| {
                Finding::new(
                    format!(
                        "`{name}` declares {count} methods (max {}) — implementers are forced to depend on methods they may not need; split it into smaller, role-specific interfaces (Interface Segregation Principle)",
                        self.max_methods
                    ),
                    node.span(),
                )
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use yunq_rules_engine::AstParser;

    fn method_signatures(n: usize) -> String {
        (0..n).map(|i| format!("  m{i}(): void;\n")).collect()
    }

    fn check_ts(code: &str, max_methods: usize) -> Vec<Finding> {
        let file = SourceFile::new("t.ts", code, LanguageIdentifier::typescript()).unwrap();
        let ast = yunq_parser_typescript::TypeScriptParser::new().parse(&file).unwrap();
        FatInterfaceRule::new(max_methods).check(&file, &ast)
    }

    #[test]
    fn flags_ts_interface_with_too_many_methods() {
        let code = format!("interface Big {{\n{}}}\n", method_signatures(5));
        let findings = check_ts(&code, 3);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("Big"));
        assert!(findings[0].message.contains("5 methods"));
    }

    #[test]
    fn allows_ts_interface_within_threshold() {
        let code = format!("interface Small {{\n{}}}\n", method_signatures(3));
        assert!(check_ts(&code, 8).is_empty());
    }

    #[test]
    fn does_not_count_property_signatures() {
        let code = "interface Config {\n  a: string;\n  b: number;\n  c: boolean;\n  d: string;\n}\n";
        assert!(check_ts(code, 3).is_empty());
    }

    #[test]
    fn flags_rust_trait_with_too_many_methods_mixing_signatures_and_defaults() {
        let code = "trait Big {\n  fn a(&self);\n  fn b(&self);\n  fn c(&self);\n  fn d(&self) {}\n}\n";
        let file = SourceFile::new("t.rs", code, LanguageIdentifier::rust()).unwrap();
        let ast = yunq_parser_rust::RustParser::new().parse(&file).unwrap();
        let findings = FatInterfaceRule::new(3).check(&file, &ast);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("Big"));
        assert!(findings[0].message.contains("4 methods"));
    }

    #[test]
    fn allows_rust_trait_within_threshold() {
        let code = "trait Small {\n  fn a(&self);\n  fn b(&self);\n}\n";
        let file = SourceFile::new("t.rs", code, LanguageIdentifier::rust()).unwrap();
        let ast = yunq_parser_rust::RustParser::new().parse(&file).unwrap();
        assert!(FatInterfaceRule::new(8).check(&file, &ast).is_empty());
    }

    #[test]
    fn does_not_apply_to_python() {
        assert!(!FatInterfaceRule::default().applies_to(&LanguageIdentifier::python()));
    }
}
