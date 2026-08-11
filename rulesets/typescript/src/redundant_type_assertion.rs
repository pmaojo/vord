//! Rule: flags `expr as T` assertions that provably don't narrow or widen
//! anything, without needing a full type checker: a literal asserted to its
//! own obvious primitive type (`"x" as string`, `42 as number`,
//! `true as boolean`), and a chained assertion that re-asserts the same
//! type its own operand was just asserted to (`x as Foo as Foo`). Both are
//! structurally redundant regardless of what `x`'s inferred type is.

use vord_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use vord_rules_engine::{Finding, Rule, RuleId, RuleMetadata, Severity};

use crate::common::is_other;

fn unwrap_parens(node: &AstNode) -> &AstNode {
    let mut current = node;
    while is_other(current, "parenthesized_expression") {
        match current.children() {
            [inner] => current = inner,
            _ => break,
        }
    }
    current
}

/// The primitive type name a literal node trivially has, if any.
fn literal_own_type(node: &AstNode) -> Option<&'static str> {
    match node.kind() {
        NodeKind::StringLiteral => Some("string"),
        NodeKind::Other(k) if k.as_ref() == "number" => Some("number"),
        NodeKind::Other(k) if k.as_ref() == "true" || k.as_ref() == "false" => Some("boolean"),
        _ => None,
    }
}

fn flagged_assertion(node: &AstNode) -> Option<&AstNode> {
    if !is_other(node, "as_expression") {
        return None;
    }
    let [operand, asserted_type] = node.children() else {
        return None;
    };
    if is_other(asserted_type, "predefined_type") && literal_own_type(operand) == Some(asserted_type.text()) {
        return Some(node);
    }
    let inner = unwrap_parens(operand);
    if is_other(inner, "as_expression") {
        let [_inner_operand, inner_type] = inner.children() else {
            return None;
        };
        if inner_type.text() == asserted_type.text() {
            return Some(node);
        }
    }
    None
}

pub struct RedundantTypeAssertionRule {
    id: RuleId,
}

impl RedundantTypeAssertionRule {
    pub fn new() -> Self {
        Self {
            id: RuleId::new("typescript:redundant-type-assertion").expect("valid rule id"),
        }
    }
}

impl Default for RedundantTypeAssertionRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for RedundantTypeAssertionRule {
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
            description: "This `as` assertion doesn't change the type of the expression — either a literal is asserted to its own obvious type, or a chained assertion re-asserts a type its operand was already asserted to.".into(),
            tags: vec!["typescript".into(), "clarity".into()],
            cwe: None,
            produces_hotspots: false,
        }
    }

    fn check(&self, _file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        ast.descendants()
            .filter_map(flagged_assertion)
            .map(|n| {
                Finding::new(
                    "this assertion is unnecessary since it does not change the type of the expression",
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
        RedundantTypeAssertionRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_string_literal_asserted_to_string() {
        assert_eq!(check("const a = 'x' as string;\n").len(), 1);
    }

    #[test]
    fn flags_number_literal_asserted_to_number() {
        assert_eq!(check("const b = 42 as number;\n").len(), 1);
    }

    #[test]
    fn flags_boolean_literal_asserted_to_boolean() {
        assert_eq!(check("const c = true as boolean;\n").len(), 1);
    }

    #[test]
    fn flags_chained_assertion_to_the_same_type() {
        assert_eq!(check("const d = (x as Foo) as Foo;\n").len(), 1);
    }

    #[test]
    fn allows_chained_assertion_to_a_different_type() {
        assert!(check("const e = x as unknown as Bar;\n").is_empty());
    }

    #[test]
    fn allows_string_literal_asserted_to_a_narrower_type() {
        assert!(check("const f = 'x' as 'x';\n").is_empty());
    }

    #[test]
    fn allows_plain_identifier_assertion() {
        assert!(check("const g = value as Foo;\n").is_empty());
    }
}
