//! Rule: flags a `type` alias whose definition nests conditional types
//! (`A extends B ? X : Y`) three or more levels deep. TypeScript's
//! conditional types are Turing-complete, and a deeply nested chain of them
//! is effectively a small program encoded in the type system — powerful,
//! but nearly unreadable and painful to debug when it produces the wrong
//! type. Prefer splitting it into named helper type aliases, one
//! conditional per alias.

use vord_ast::{AstNode, LanguageIdentifier, SourceFile};
use vord_rules_engine::{Finding, IssueType, Rule, RuleId, RuleMetadata, Severity};

use crate::common::is_other;

const DEPTH_THRESHOLD: u32 = 3;

fn conditional_depth(node: &AstNode) -> u32 {
    let own = u32::from(is_other(node, "conditional_type"));
    let deepest_child = node.children().iter().map(conditional_depth).max().unwrap_or(0);
    own + deepest_child
}

pub struct TypeLevelLogicTooComplexRule {
    id: RuleId,
}

impl TypeLevelLogicTooComplexRule {
    pub fn new() -> Self {
        Self {
            id: RuleId::new("typescript:type-level-logic-too-complex").expect("valid rule id"),
        }
    }
}

impl Default for TypeLevelLogicTooComplexRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for TypeLevelLogicTooComplexRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn applies_to(&self, lang: &LanguageIdentifier) -> bool {
        *lang == LanguageIdentifier::typescript()
    }

    fn default_severity(&self) -> Severity {
        Severity::Major
    }

    fn issue_type(&self) -> IssueType {
        IssueType::CodeSmell
    }

    fn remediation_effort_minutes(&self) -> u32 {
        20
    }

    fn metadata(&self) -> RuleMetadata {
        RuleMetadata {
            description: "This type alias nests conditional types 3+ levels deep, effectively encoding a small program in the type system. Split it into named helper type aliases, one conditional per alias.".into(),
            tags: vec!["typescript".into(), "maintainability".into(), "clarity".into()],
            cwe: None,
            produces_hotspots: false,
        }
    }

    fn check(&self, _file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        ast.descendants()
            .filter(|n| is_other(n, "type_alias_declaration"))
            .filter(|n| conditional_depth(n) >= DEPTH_THRESHOLD)
            .map(|n| {
                Finding::new(
                    "this type alias nests conditional types 3+ levels deep; split it into named helper aliases",
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
        TypeLevelLogicTooComplexRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_three_levels_of_nested_conditional_types() {
        let code = "type X<T> = T extends string ? (T extends 'a' ? 1 : (T extends 'b' ? 2 : 3)) : never;\n";
        assert_eq!(check(code).len(), 1);
    }

    #[test]
    fn allows_single_conditional_type() {
        assert!(check("type X<T> = T extends string ? true : false;\n").is_empty());
    }

    #[test]
    fn allows_two_levels_of_nesting() {
        let code = "type X<T> = T extends string ? (T extends 'a' ? 1 : 2) : never;\n";
        assert!(check(code).is_empty());
    }

    #[test]
    fn allows_alias_with_no_conditional_type() {
        assert!(check("type X = { a: string };\n").is_empty());
    }
}
