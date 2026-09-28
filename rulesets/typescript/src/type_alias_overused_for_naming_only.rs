//! Rule: flags `type Foo = string;` (or `number`/`boolean`/`bigint`) — a
//! type alias whose value is a bare primitive keyword. Unlike a branded
//! type, this gives the compiler nothing to distinguish `Foo` from any
//! other `string` at any call site: a plain `string` is accepted anywhere
//! `Foo` is expected and vice versa, so the alias is purely a naming
//! convenience with no type-safety benefit — easy to mistake for the
//! nominal typing it doesn't actually provide.
//!
//! Deliberately narrower than [`crate::redundant_type_alias`], which flags
//! an alias of *another named type* (`type Foo = Bar`); this rule targets
//! the complementary case that one explicitly allows through: aliasing a
//! primitive directly.

use vord_ast::{AstNode, LanguageIdentifier, SourceFile};
use vord_rules_engine::{Finding, IssueType, Rule, RuleId, RuleMetadata, Severity};

use crate::common::is_other;

const PRIMITIVES: [&str; 4] = ["string", "number", "boolean", "bigint"];

fn flagged(node: &AstNode) -> Option<&AstNode> {
    if !is_other(node, "type_alias_declaration") {
        return None;
    }
    let [_name, value] = node.children() else {
        return None;
    };
    (is_other(value, "predefined_type") && PRIMITIVES.contains(&value.text())).then_some(node)
}

pub struct TypeAliasOverusedForNamingOnlyRule {
    id: RuleId,
}

impl TypeAliasOverusedForNamingOnlyRule {
    pub fn new() -> Self {
        Self {
            id: RuleId::new("typescript:type-alias-overused-for-naming-only")
                .expect("valid rule id"),
        }
    }
}

impl Default for TypeAliasOverusedForNamingOnlyRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for TypeAliasOverusedForNamingOnlyRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn applies_to(&self, lang: &LanguageIdentifier) -> bool {
        *lang == LanguageIdentifier::typescript()
    }

    fn default_severity(&self) -> Severity {
        Severity::Info
    }

    fn issue_type(&self) -> IssueType {
        IssueType::CodeSmell
    }

    fn remediation_effort_minutes(&self) -> u32 {
        10
    }

    fn metadata(&self) -> RuleMetadata {
        RuleMetadata {
            description: "This type alias just renames a bare primitive, so the compiler treats it exactly like the primitive everywhere — a plain value type-checks wherever the alias is expected. If distinct identity matters, use a branded type instead of a plain alias.".into(),
            tags: vec!["typescript".into(), "clarity".into()],
            cwe: None,
            produces_hotspots: false,
        }
    }

    fn check(&self, _file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        ast.descendants()
            .filter_map(flagged)
            .map(|n| {
                Finding::new(
                    "this type alias just renames a bare primitive with no added type safety; use a branded type if distinct identity matters",
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
        TypeAliasOverusedForNamingOnlyRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_alias_of_string() {
        assert_eq!(check("type UserId = string;\n").len(), 1);
    }

    #[test]
    fn flags_alias_of_number() {
        assert_eq!(check("type Age = number;\n").len(), 1);
    }

    #[test]
    fn allows_alias_with_object_shape() {
        assert!(check("type Foo = { a: string };\n").is_empty());
    }

    #[test]
    fn allows_alias_of_another_named_type() {
        assert!(check("type Id = SomeOtherType;\n").is_empty());
    }

    #[test]
    fn allows_alias_of_union() {
        assert!(check("type Status = 'a' | 'b';\n").is_empty());
    }

    #[test]
    fn allows_branded_type_alias() {
        assert!(check("type UserId = string & { readonly __brand: 'UserId' };\n").is_empty());
    }
}
