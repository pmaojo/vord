//! Rule: flags `expr as T as T` — a chained assertion that re-asserts the
//! same type its own operand was just asserted to (`x as Foo as Foo`). The
//! outer assertion is structurally redundant regardless of what `x`'s
//! inferred type is, since the inner assertion already forced the operand
//! to `T`.
//!
//! A literal asserted to its own apparent primitive type (`"x" as string`)
//! is deliberately *not* flagged here: without a real type checker, this
//! analyzer can't tell that case apart from an intentional widening of a
//! literal type to its base primitive (e.g. `let s = "draft" as string` so
//! `s` isn't narrowed to the literal type `"draft"`), which is a legitimate,
//! meaningful use of `as` — not a no-op.

use vord_ast::{AstNode, LanguageIdentifier, SourceFile};
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

fn flagged_assertion(node: &AstNode) -> Option<&AstNode> {
    if !is_other(node, "as_expression") {
        return None;
    }
    let [operand, asserted_type] = node.children() else {
        return None;
    };
    let inner = unwrap_parens(operand);
    if !is_other(inner, "as_expression") {
        return None;
    }
    let [_inner_operand, inner_type] = inner.children() else {
        return None;
    };
    (inner_type.text() == asserted_type.text()).then_some(node)
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
            description: "This chained `as` assertion re-asserts the same type its operand was already asserted to, so it doesn't change the type of the expression.".into(),
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
    fn flags_chained_assertion_to_the_same_type() {
        assert_eq!(check("const d = (x as Foo) as Foo;\n").len(), 1);
    }

    #[test]
    fn flags_chained_assertion_without_parens() {
        assert_eq!(check("const h = x as Foo as Foo;\n").len(), 1);
    }

    #[test]
    fn allows_chained_assertion_to_a_different_type() {
        assert!(check("const e = x as unknown as Bar;\n").is_empty());
    }

    #[test]
    fn allows_plain_identifier_assertion() {
        assert!(check("const g = value as Foo;\n").is_empty());
    }

    #[test]
    fn allows_string_literal_widened_to_string() {
        // Intentional widening of a literal type to its base primitive —
        // not a no-op without a real type checker to confirm it.
        assert!(check("const a = 'draft' as string;\n").is_empty());
    }

    #[test]
    fn allows_number_literal_widened_to_number() {
        assert!(check("const b = 42 as number;\n").is_empty());
    }

    #[test]
    fn allows_boolean_literal_widened_to_boolean() {
        assert!(check("const c = true as boolean;\n").is_empty());
    }
}
