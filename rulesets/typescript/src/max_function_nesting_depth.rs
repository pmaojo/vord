//! Rule: flags a function (`function`, `function` expression, arrow
//! function, or method) nested more than 4 levels deep inside other
//! functions — e.g. a callback inside a callback inside a hook inside a
//! component's render body. Each extra level of function nesting adds a
//! separate closure scope a reader has to hold in mind at once; beyond a
//! handful of levels that tracking cost dominates.

use vord_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use vord_rules_engine::{Finding, Rule, RuleId, RuleMetadata, Severity};

const MAX_DEPTH: u32 = 4;

fn walk<'a>(node: &'a AstNode, depth: u32, findings: &mut Vec<(&'a AstNode, u32)>) {
    let next_depth = if *node.kind() == NodeKind::FunctionDef {
        let next_depth = depth + 1;
        if next_depth > MAX_DEPTH {
            findings.push((node, next_depth));
        }
        next_depth
    } else {
        depth
    };
    for child in node.children() {
        walk(child, next_depth, findings);
    }
}

pub struct MaxFunctionNestingDepthRule {
    id: RuleId,
}

impl MaxFunctionNestingDepthRule {
    pub fn new() -> Self {
        Self {
            id: RuleId::new("typescript:max-function-nesting-depth").expect("valid rule id"),
        }
    }
}

impl Default for MaxFunctionNestingDepthRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for MaxFunctionNestingDepthRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn applies_to(&self, lang: &LanguageIdentifier) -> bool {
        *lang == LanguageIdentifier::typescript()
    }

    fn default_severity(&self) -> Severity {
        Severity::Major
    }

    fn remediation_effort_minutes(&self) -> u32 {
        15
    }

    fn metadata(&self) -> RuleMetadata {
        RuleMetadata {
            description: "A function nested more than 4 levels deep inside other functions forces a reader to hold that many closure scopes in mind at once; extract inner functions to reduce the nesting.".into(),
            tags: vec!["typescript".into(), "maintainability".into(), "readability".into()],
            cwe: None,
            produces_hotspots: false,
        }
    }

    fn check(&self, _file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        let mut hits = Vec::new();
        walk(ast, 0, &mut hits);
        hits.into_iter()
            .map(|(n, depth)| {
                Finding::new(
                    format!("refactor this code to not nest functions more than {MAX_DEPTH} levels deep (nested {depth} levels here)"),
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
        MaxFunctionNestingDepthRule::new().check(&file, &ast)
    }

    #[test]
    fn allows_functions_nested_up_to_four_levels() {
        let code = "function a() {\n  return function b() {\n    return function c() {\n      return function d() {\n        return 1;\n      };\n    };\n  };\n}\n";
        assert!(check(code).is_empty());
    }

    #[test]
    fn flags_a_function_nested_five_levels_deep() {
        let code = "function a() {\n  return function b() {\n    return function c() {\n      return function d() {\n        return function e() {\n          return 1;\n        };\n      };\n    };\n  };\n}\n";
        let findings = check(code);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains('5'));
    }

    #[test]
    fn flags_deeply_nested_arrow_callbacks() {
        let code = "const f = () => () => () => () => () => 1;\n";
        assert_eq!(check(code).len(), 1);
    }

    #[test]
    fn allows_sibling_functions_at_the_same_depth() {
        let code = "function outer() {\n  const a = () => 1;\n  const b = () => 2;\n  return a() + b();\n}\n";
        assert!(check(code).is_empty());
    }
}
