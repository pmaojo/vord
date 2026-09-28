//! Rule: flags a ternary that renders JSX on one branch and `null` on the
//! other (`cond ? <Foo /> : null` or `cond ? null : <Foo />`), which is
//! better written as a short-circuit (`cond && <Foo />` /
//! `!cond && <Foo />`).

use vord_ast::{AstNode, LanguageIdentifier, SourceFile};
use vord_rules_engine::{declare_rule_id, Finding, IssueType, Rule, RuleId, RuleMetadata, Severity};

use crate::common::{is_jsx_kind, is_other};

declare_rule_id!(JsxTernaryNullRule, "react:jsx-ternary-null");

fn is_null_literal(node: &AstNode) -> bool {
    is_other(node, "null")
}

fn flagged_ternary(node: &AstNode) -> Option<&AstNode> {
    if !is_other(node, "ternary_expression") {
        return None;
    }
    let [_, consequent, alternate] = node.children() else {
        return None;
    };
    let is_null_jsx = is_null_literal(consequent) && is_jsx_kind(alternate);
    let is_jsx_null = is_jsx_kind(consequent) && is_null_literal(alternate);
    (is_null_jsx || is_jsx_null).then_some(node)
}

impl Rule for JsxTernaryNullRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn applies_to(&self, language: &LanguageIdentifier) -> bool {
        *language == LanguageIdentifier::typescript()
    }

    fn default_severity(&self) -> Severity {
        Severity::Minor
    }

    fn issue_type(&self) -> IssueType {
        IssueType::CodeSmell
    }

    fn metadata(&self) -> RuleMetadata {
        RuleMetadata {
            description: "A ternary that renders JSX on one branch and `null` on the other is better written as a short-circuit expression (`condition && <Component />`), unless `condition` can evaluate to a renderable non-boolean value such as `0`.".into(),
            tags: vec!["react".into(), "jsx".into(), "clean-code".into()],
            cwe: None,
            produces_hotspots: false,
        }
    }

    fn check(&self, _file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        ast.descendants()
            .filter_map(flagged_ternary)
            .map(|n| {
                Finding::new(
                    "prefer `condition && <Component />` over a ternary that returns null; make `condition` explicitly boolean first if it could be a renderable falsy value like `0`",
                    n.span(),
                )
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vord_ast::LanguageIdentifier;
    use vord_rules_engine::AstParser;

    fn check(code: &str) -> Vec<Finding> {
        let file = SourceFile::new("t.tsx", code, LanguageIdentifier::typescript()).unwrap();
        let ast = vord_parser_typescript::TypeScriptParser::new()
            .parse(&file)
            .unwrap();
        JsxTernaryNullRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_ternary_with_null_alternate() {
        let code = "const el = show ? <Foo /> : null;\n";
        assert_eq!(check(code).len(), 1);
    }

    #[test]
    fn flags_ternary_with_null_consequent() {
        let code = "const el = show ? null : <Foo />;\n";
        assert_eq!(check(code).len(), 1);
    }

    #[test]
    fn flags_ternary_inside_jsx_expression() {
        let code = "const el = <div>{show ? <Foo /> : null}</div>;\n";
        assert_eq!(check(code).len(), 1);
    }

    #[test]
    fn allows_ternary_with_two_jsx_branches() {
        let code = "const el = show ? <Foo /> : <Bar />;\n";
        assert!(check(code).is_empty());
    }

    #[test]
    fn allows_ternary_with_non_jsx_branches() {
        let code = "const x = show ? 1 : null;\n";
        assert!(check(code).is_empty());
    }

    #[test]
    fn allows_short_circuit_expression() {
        let code = "const el = <div>{show && <Foo />}</div>;\n";
        assert!(check(code).is_empty());
    }
}
