use vord_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile, Span};
use vord_rules_engine::{Finding, IssueType, Rule, RuleId, Severity};

use crate::common::{impl_trait_is, is_other, self_type_of_impl};

fn derive_names(attr_item: &AstNode) -> Vec<&str> {
    let Some(attribute) = attr_item
        .first_child()
        .filter(|a| is_other(a.kind(), "attribute"))
    else {
        return Vec::new();
    };
    let is_derive = attribute
        .first_child()
        .is_some_and(|i| *i.kind() == NodeKind::Identifier && i.text() == "derive");
    let Some(token_tree) = is_derive.then(|| attribute.children().get(1)).flatten() else {
        return Vec::new();
    };
    token_tree
        .children()
        .iter()
        .filter(|c| *c.kind() == NodeKind::Identifier)
        .map(|c| c.text())
        .collect()
}

fn item_name(node: &AstNode) -> Option<&str> {
    let first = node.first_child()?;
    is_other(first.kind(), "type_identifier").then(|| first.text())
}

/// Recursively finds every `struct`/`enum` immediately preceded (allowing
/// intervening comments and other attributes) by a `#[derive(..., Hash,
/// ...)]`, and records its name. Needs true sibling adjacency — unlike a
/// flat `ast.descendants()` scan — so it walks each node's own children in
/// source order instead.
fn collect_hash_derived(node: &AstNode, out: &mut Vec<(String, Span)>) {
    let mut pending: Option<Span> = None;
    for child in node.children() {
        if is_other(child.kind(), "attribute_item") {
            if derive_names(child).contains(&"Hash") {
                pending = Some(child.span());
            }
        } else if is_other(child.kind(), "struct_item") || is_other(child.kind(), "enum_item") {
            if let Some(span) = pending.take() {
                if let Some(name) = item_name(child) {
                    out.push((name.to_string(), span));
                }
            }
        } else if *child.kind() != NodeKind::Comment {
            pending = None;
        }
        collect_hash_derived(child, out);
    }
}

fn manual_partial_eq_targets(ast: &AstNode) -> Vec<&str> {
    ast.descendants()
        .filter(|n| is_other(n.kind(), "impl_item") && impl_trait_is(n, "PartialEq"))
        .filter_map(self_type_of_impl)
        .map(|self_ty| {
            let base = self_ty.text().split('<').next().unwrap_or(self_ty.text());
            base.rsplit("::").next().unwrap_or(base)
        })
        .collect()
}

/// `#[derive(Hash)]` generates a hash from every field, in field-declaration
/// order. A hand-written `PartialEq` on the same type is under no obligation
/// to agree with that — if it skips a field, compares fields in a different
/// combination, or normalizes values before comparing, two values it
/// considers equal can still hash differently. That breaks the `Hash`/`Eq`
/// contract (`a == b` must imply `hash(a) == hash(b)`) silently: the type
/// still compiles and looks correct, but `HashMap`/`HashSet` lookups using
/// it start missing entries that are logically present. Mirrors clippy's
/// `derived_hash_with_manual_eq` (`correctness`, deny-by-default). Same-file
/// only: a manual `PartialEq` declared in another file isn't seen.
pub struct DeriveHashManualPartialEqRule {
    id: RuleId,
}

impl DeriveHashManualPartialEqRule {
    pub fn new() -> Self {
        Self {
            id: RuleId::new("rust:derive-hash-manual-partial-eq").expect("valid rule id"),
        }
    }
}

impl Default for DeriveHashManualPartialEqRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for DeriveHashManualPartialEqRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn applies_to(&self, language: &LanguageIdentifier) -> bool {
        *language == LanguageIdentifier::rust()
    }

    fn default_severity(&self) -> Severity {
        Severity::Major
    }

    fn issue_type(&self) -> IssueType {
        IssueType::Bug
    }

    fn remediation_effort_minutes(&self) -> u32 {
        20
    }

    fn metadata(&self) -> vord_rules_engine::RuleMetadata {
        vord_rules_engine::RuleMetadata {
            description: "A type derives `Hash` but implements `PartialEq` by hand; if the two \
                don't agree field-for-field, the `Hash`/`Eq` contract breaks and `HashMap`/ \
                `HashSet` lookups silently start missing entries. Derive both together, or \
                implement `Hash` by hand to match."
                .into(),
            tags: vec!["correctness".into(), "rust".into()],
            cwe: None,
            produces_hotspots: false,
        }
    }

    fn check(&self, file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        let test_ranges = vord_rules_engine::rust_test_module_ranges(file.content());
        let mut hash_derived = Vec::new();
        collect_hash_derived(ast, &mut hash_derived);
        let manual_eq_targets = manual_partial_eq_targets(ast);

        hash_derived
            .into_iter()
            .filter(|(name, _)| manual_eq_targets.contains(&name.as_str()))
            .filter(|(_, span)| !vord_rules_engine::in_ranges(&test_ranges, span.start_line))
            .map(|(name, span)| {
                Finding::new(
                    format!(
                        "`{name}` derives `Hash` but implements `PartialEq` manually; make sure \
                        the manual comparison agrees field-for-field with the derived hash, or \
                        the `Hash`/`Eq` contract breaks"
                    ),
                    span,
                )
            })
            .collect()
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
        DeriveHashManualPartialEqRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_derived_hash_with_manual_partial_eq() {
        let findings = check(
            "#[derive(Hash, Eq)]\nstruct Foo(u32);\nimpl PartialEq for Foo {\n    fn eq(&self, o: &Self) -> bool { true }\n}\n",
        );
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn flags_enum_variant_too() {
        let findings = check(
            "#[derive(Debug, Hash)]\nenum Foo { A, B }\nimpl PartialEq for Foo {\n    fn eq(&self, o: &Self) -> bool { true }\n}\n",
        );
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn ignores_fully_derived_type() {
        assert!(check("#[derive(Hash, PartialEq, Eq)]\nstruct Foo(u32);\n").is_empty());
    }

    #[test]
    fn ignores_manual_eq_without_derived_hash() {
        assert!(check(
            "#[derive(Debug)]\nstruct Foo(u32);\nimpl PartialEq for Foo {\n    fn eq(&self, o: &Self) -> bool { true }\n}\n"
        )
        .is_empty());
    }

    #[test]
    fn ignores_unrelated_manual_impls() {
        assert!(check(
            "#[derive(Hash)]\nstruct Foo(u32);\nimpl Clone for Foo {\n    fn clone(&self) -> Self { Self(0) }\n}\n"
        )
        .is_empty());
    }

    #[test]
    fn ignores_derive_hash_manual_partial_eq_inside_a_cfg_test_module() {
        let code = "fn prod() {}\n\n#[cfg(test)]\nmod tests {\n    #[derive(Hash, Eq)]\n    struct Foo(u32);\n    impl PartialEq for Foo {\n        fn eq(&self, o: &Self) -> bool { true }\n    }\n}\n";
        assert!(check(code).is_empty());
    }
}
