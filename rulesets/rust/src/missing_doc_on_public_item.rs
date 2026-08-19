use vord_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use vord_rules_engine::{Finding, IssueType, Rule, RuleId, Severity};

use crate::common::is_other;

fn is_plain_pub(node: &AstNode) -> bool {
    node.text()
        .trim_start()
        .strip_prefix("pub")
        .is_some_and(|rest| rest.starts_with(|c: char| c.is_whitespace()))
}

/// Whether a `///`/`/**`/`//!` doc comment appears directly above
/// `start_line` (1-based), skipping over any `#[...]` attribute lines in
/// between (a `#[derive(..)]` commonly sits between the doc comment and the
/// item it documents).
fn has_doc_comment_directly_above(lines: &[&str], start_line: u32) -> bool {
    for line in lines[..start_line.saturating_sub(1) as usize].iter().rev() {
        let trimmed = line.trim();
        if trimmed.starts_with("#[") {
            continue;
        }
        return trimmed.starts_with("///")
            || trimmed.starts_with("/**")
            || trimmed.starts_with("//!");
    }
    false
}

fn item_kind_label(node: &AstNode) -> Option<&'static str> {
    if *node.kind() == NodeKind::FunctionDef {
        return Some("function");
    }
    match node.kind() {
        NodeKind::Other(k) if k.as_ref() == "struct_item" => Some("struct"),
        NodeKind::Other(k) if k.as_ref() == "enum_item" => Some("enum"),
        NodeKind::Other(k) if k.as_ref() == "trait_item" => Some("trait"),
        _ => None,
    }
}

/// Walks only module-level structure — a file's top level and any nested
/// `mod { .. }` bodies — without descending into function bodies, `impl`
/// blocks, or struct/enum bodies: this rule only judges module-level API
/// surface, not every `pub` field or associated method, to keep it quiet
/// on the far larger, noisier surface those would add.
fn walk_module(node: &AstNode, lines: &[&str], test_ranges: &[(u32, u32)], out: &mut Vec<Finding>) {
    for child in node.children() {
        if let Some(label) = item_kind_label(child) {
            if is_plain_pub(child)
                && !vord_rules_engine::in_ranges(test_ranges, child.span().start_line)
                && !has_doc_comment_directly_above(lines, child.span().start_line)
            {
                out.push(Finding::new(
                    format!("this public {label} has no `///` doc comment"),
                    child.span(),
                ));
            }
        }

        if is_other(child.kind(), "mod_item") {
            if let Some(decls) = child
                .children()
                .iter()
                .find(|c| is_other(c.kind(), "declaration_list"))
            {
                walk_module(decls, lines, test_ranges, out);
            }
        }
    }
}

/// A `pub` struct, enum, trait, or function with no `///` doc comment
/// leaves the crate's public API undocumented: `cargo doc` renders an
/// empty description, and downstream users have to read the
/// implementation to learn what the item does. Scoped to module-level
/// items (not struct fields or `impl` methods) to keep the signal focused
/// on the surface a crate actually publishes as its top-level API.
pub struct MissingDocOnPublicItemRule {
    id: RuleId,
}

impl MissingDocOnPublicItemRule {
    pub fn new() -> Self {
        Self {
            id: RuleId::new("rust:missing-doc-on-public-item").expect("valid rule id"),
        }
    }
}

impl Default for MissingDocOnPublicItemRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for MissingDocOnPublicItemRule {
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

    fn remediation_effort_minutes(&self) -> u32 {
        5
    }

    fn metadata(&self) -> vord_rules_engine::RuleMetadata {
        vord_rules_engine::RuleMetadata {
            description: "A public struct, enum, trait, or function with no `///` doc comment \
                leaves the crate's published API undocumented in `cargo doc` output."
                .into(),
            tags: vec!["documentation".into(), "rust".into()],
            cwe: None,
            produces_hotspots: false,
        }
    }

    fn check(&self, file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        let lines: Vec<&str> = file.content().lines().collect();
        let test_ranges = vord_rules_engine::rust_test_module_ranges(file.content());
        let mut out = Vec::new();
        walk_module(ast, &lines, &test_ranges, &mut out);
        out
    }
}

#[cfg(test)]
mod tests {
    use vord_ast::SourceFile;
    use vord_rules_engine::AstParser;

    use super::*;

    fn check(code: &str) -> Vec<Finding> {
        let file = SourceFile::new("t.rs", code, LanguageIdentifier::rust()).unwrap();
        let ast = vord_parser_rust::RustParser::new().parse(&file).unwrap();
        MissingDocOnPublicItemRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_undocumented_pub_struct() {
        let findings = check("pub struct Widget {\n    pub id: u32,\n}\n");
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn flags_undocumented_pub_fn() {
        let findings = check("pub fn compute() -> u32 { 1 }\n");
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn flags_undocumented_pub_enum() {
        let findings = check("pub enum State {\n    On,\n    Off,\n}\n");
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn flags_undocumented_pub_trait() {
        let findings = check("pub trait Widget {\n    fn id(&self) -> u32;\n}\n");
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn accepts_documented_pub_struct() {
        assert!(check("/// A widget.\npub struct Widget {\n    pub id: u32,\n}\n").is_empty());
    }

    #[test]
    fn accepts_doc_comment_with_derive_attribute_between() {
        assert!(
            check(
                "/// A widget.\n#[derive(Debug, Clone)]\npub struct Widget {\n    pub id: u32,\n}\n"
            )
            .is_empty()
        );
    }

    #[test]
    fn ignores_private_items() {
        assert!(check("struct Widget {\n    id: u32,\n}\n").is_empty());
    }

    #[test]
    fn ignores_pub_crate_items() {
        assert!(check("pub(crate) fn helper() {}\n").is_empty());
    }

    #[test]
    fn ignores_fields_and_methods_inside_documented_struct_and_impl() {
        let code = "/// A widget.\npub struct Widget {\n    pub id: u32,\n}\n\nimpl Widget {\n    pub fn id(&self) -> u32 {\n        self.id\n    }\n}\n";
        assert!(check(code).is_empty());
    }

    #[test]
    fn flags_undocumented_pub_item_inside_a_nested_mod() {
        let findings = check("mod inner {\n    pub struct Widget;\n}\n");
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn ignores_missing_doc_on_public_item_inside_a_cfg_test_module() {
        let code = "fn prod() {}\n\n#[cfg(test)]\nmod tests {\n    pub struct Widget;\n}\n";
        assert!(check(code).is_empty());
    }
}
