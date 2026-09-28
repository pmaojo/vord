//! Rule: flags a rest parameter (`...args`) with no type annotation. An
//! untyped rest parameter is implicitly `any[]`, silently disabling type
//! checking on every element pulled out of it — the parameter-list
//! equivalent of `no_explicit_any`.

use vord_ast::{AstNode, LanguageIdentifier, SourceFile};
use vord_rules_engine::{Finding, IssueType, Rule, RuleId, RuleMetadata, Severity};

use crate::common::is_other;

fn flagged(param: &AstNode) -> bool {
    (is_other(param, "required_parameter") || is_other(param, "optional_parameter"))
        && param.first_child().is_some_and(|c| is_other(c, "rest_pattern"))
        && !param.children().iter().any(|c| is_other(c, "type_annotation"))
}

pub struct ImplicitAnyOnRestParamsRule {
    id: RuleId,
}

impl ImplicitAnyOnRestParamsRule {
    pub fn new() -> Self {
        Self {
            id: RuleId::new("typescript:implicit-any-on-rest-params").expect("valid rule id"),
        }
    }
}

impl Default for ImplicitAnyOnRestParamsRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for ImplicitAnyOnRestParamsRule {
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
        3
    }

    fn metadata(&self) -> RuleMetadata {
        RuleMetadata {
            description: "This rest parameter has no type annotation, so it's implicitly `any[]` — every element pulled out of it skips type checking. Add an explicit element type, e.g. `...args: string[]`.".into(),
            tags: vec!["typescript".into(), "type-safety".into()],
            cwe: Some(704),
            produces_hotspots: false,
        }
    }

    fn check(&self, _file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        ast.descendants()
            .filter(|n| flagged(n))
            .map(|n| {
                Finding::new(
                    "this rest parameter has no type annotation, so it is implicitly `any[]`; add an explicit element type",
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
        ImplicitAnyOnRestParamsRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_untyped_rest_param() {
        assert_eq!(check("function f(...args) {}\n").len(), 1);
    }

    #[test]
    fn allows_typed_rest_param() {
        assert!(check("function f(...args: number[]) {}\n").is_empty());
    }

    #[test]
    fn allows_typed_rest_param_with_tuple_type() {
        assert!(check("function f(...args: [string, number]) {}\n").is_empty());
    }

    #[test]
    fn flags_untyped_rest_param_in_arrow_function() {
        assert_eq!(check("const f = (...args) => args.length;\n").len(), 1);
    }

    #[test]
    fn allows_function_with_no_rest_param() {
        assert!(check("function f(a: number, b: string) {}\n").is_empty());
    }
}
