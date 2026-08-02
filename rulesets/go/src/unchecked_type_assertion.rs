//! Rule: flags `x.(T)` used in its single-value form, which panics if `x`'s
//! dynamic type isn't `T` — as opposed to the two-value "comma-ok" form
//! (`v, ok := x.(T)`), which reports failure instead of panicking. Mirrors
//! `golangci-lint`'s `forcetypeassert` linter. Go's grammar only allows the
//! comma-ok form directly as the sole right-hand side of a `:=`/`=` with
//! exactly two targets (`v, ok := ...`) or a type switch (`switch x :=
//! y.(type)`, a distinct grammar node this rule doesn't touch); every other
//! position — nested in a larger expression, a function argument, a bound
//! single-target assignment — is necessarily the panicking form, since
//! Go's syntax doesn't allow comma-ok there at all.

use vord_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use vord_rules_engine::{
    Finding, IssueType, Rule, RuleId, RuleMetadata, Severity, declare_rule_id,
};

use crate::common::is_other;

/// Walks `node`, collecting every `type_assertion_expression` used in its
/// panicking single-value form. A `VariableDecl`/`Assignment` whose sole
/// right-hand expression is a type assertion is the one shape that *can* be
/// the safe comma-ok form — decided by its left-hand target count — so it's
/// special-cased and excluded from the generic fallthrough below, which
/// flags every other type assertion unconditionally.
fn collect_unchecked<'a>(node: &'a AstNode, out: &mut Vec<&'a AstNode>) {
    if matches!(node.kind(), NodeKind::VariableDecl | NodeKind::Assignment) {
        if let [names, values] = node.children() {
            if let [sole] = values.children() {
                if is_other(sole.kind(), "type_assertion_expression") {
                    if names.children().len() < 2 {
                        out.push(sole);
                    }
                    for c in names.children() {
                        collect_unchecked(c, out);
                    }
                    for c in sole.children() {
                        collect_unchecked(c, out);
                    }
                    return;
                }
            }
        }
    }
    if is_other(node.kind(), "type_assertion_expression") {
        out.push(node);
    }
    for c in node.children() {
        collect_unchecked(c, out);
    }
}

declare_rule_id!(UncheckedTypeAssertionRule, "go:unchecked-type-assertion");

impl Rule for UncheckedTypeAssertionRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn applies_to(&self, language: &LanguageIdentifier) -> bool {
        *language == LanguageIdentifier::go()
    }

    fn default_severity(&self) -> Severity {
        Severity::Major
    }

    fn issue_type(&self) -> IssueType {
        IssueType::Bug
    }

    fn metadata(&self) -> RuleMetadata {
        RuleMetadata {
            description: "A single-value type assertion (`x.(T)`) panics if `x`'s dynamic type \
                isn't `T`; use the two-value comma-ok form (`v, ok := x.(T)`) and handle the \
                `!ok` case instead."
                .into(),
            tags: vec!["go".into(), "correctness".into()],
            cwe: None,
            produces_hotspots: false,
        }
    }

    fn check(&self, _file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        let mut out = Vec::new();
        collect_unchecked(ast, &mut out);
        out.into_iter()
            .map(|assertion| {
                Finding::new(
                    format!(
                        "`{}` panics if the underlying type doesn't match; use the two-value \
                        comma-ok form (`v, ok := ...`) instead",
                        assertion.text()
                    ),
                    assertion.span(),
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
        let file = SourceFile::new("t.go", code, LanguageIdentifier::go()).unwrap();
        let ast = vord_parser_go::GoParser::new().parse(&file).unwrap();
        UncheckedTypeAssertionRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_single_value_declaration() {
        assert_eq!(
            check("package main\nfunc f(x interface{}) {\n\tv := x.(string)\n\t_ = v\n}\n").len(),
            1
        );
    }

    #[test]
    fn flags_single_value_assignment() {
        assert_eq!(
            check("package main\nfunc f(x interface{}) {\n\tvar v string\n\tv = x.(string)\n\t_ = v\n}\n").len(),
            1
        );
    }

    #[test]
    fn flags_nested_in_argument() {
        assert_eq!(
            check("package main\nfunc f(x interface{}) {\n\tfmt.Println(x.(string))\n}\n").len(),
            1
        );
    }

    #[test]
    fn allows_comma_ok_declaration() {
        assert!(
            check(
                "package main\nfunc f(x interface{}) {\n\tv, ok := x.(string)\n\t_, _ = v, ok\n}\n"
            )
            .is_empty()
        );
    }

    #[test]
    fn allows_comma_ok_assignment() {
        assert!(check(
            "package main\nfunc f(x interface{}) {\n\tvar v string\n\tvar ok bool\n\tv, ok = x.(string)\n\t_, _ = v, ok\n}\n"
        )
        .is_empty());
    }
}
