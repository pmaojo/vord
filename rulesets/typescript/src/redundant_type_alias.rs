//! Rule: flags `type Foo = Bar;` where the right-hand side is just another
//! named type with no added structure — the alias adds a name but no new
//! shape, so callers can use `Bar` directly (or the alias should add
//! members if that was the intent).

use vord_ast::{AstNode, LanguageIdentifier, SourceFile};
use vord_rules_engine::{Finding, Rule, RuleId, RuleMetadata, Severity};

use crate::common::is_other;

fn flagged_alias(node: &AstNode) -> Option<&AstNode> {
    if !is_other(node, "type_alias_declaration") {
        return None;
    }
    let [name, value] = node.children() else {
        return None;
    };
    if !is_other(name, "type_identifier") {
        return None;
    }
    (is_other(value, "type_identifier") && value.text() != name.text()).then_some(node)
}

pub struct RedundantTypeAliasRule {
    id: RuleId,
}

impl RedundantTypeAliasRule {
    pub fn new() -> Self {
        Self {
            id: RuleId::new("typescript:redundant-type-alias").expect("valid rule id"),
        }
    }
}

impl Default for RedundantTypeAliasRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for RedundantTypeAliasRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn applies_to(&self, lang: &LanguageIdentifier) -> bool {
        *lang == LanguageIdentifier::typescript()
    }

    fn default_severity(&self) -> Severity {
        Severity::Minor
    }

    fn remediation_effort_minutes(&self) -> u32 {
        2
    }

    fn metadata(&self) -> RuleMetadata {
        RuleMetadata {
            description: "A type alias whose value is just another named type (`type Foo = Bar`) adds a name but no new shape; use `Bar` directly, or give the alias its own members if that was the intent.".into(),
            tags: vec!["typescript".into(), "clarity".into()],
            cwe: None,
            produces_hotspots: false,
        }
    }

    fn check(&self, _file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        ast.descendants()
            .filter_map(flagged_alias)
            .map(|n| {
                Finding::new(
                    "remove this redundant type alias; it aliases another named type with no added structure",
                    n.span(),
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
        let file = SourceFile::new("t.ts", code, LanguageIdentifier::typescript()).unwrap();
        let ast = vord_parser_typescript::TypeScriptParser::new()
            .parse(&file)
            .unwrap();
        RedundantTypeAliasRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_alias_of_another_named_type() {
        assert_eq!(check("type WeddingProposal = UnknownRecord;\n").len(), 1);
    }

    #[test]
    fn allows_alias_of_primitive() {
        assert!(check("type Id = string;\n").is_empty());
    }

    #[test]
    fn allows_alias_with_object_shape() {
        assert!(check("type Foo = { a: string };\n").is_empty());
    }

    #[test]
    fn allows_alias_with_union() {
        assert!(check("type Foo = A | B;\n").is_empty());
    }
}
