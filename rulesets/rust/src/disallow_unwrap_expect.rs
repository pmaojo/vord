use vord_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use vord_rules_engine::{Finding, IssueType, Rule, RuleId, Severity, declare_rule_id};

declare_rule_id!(DisallowUnwrapExpectRule, "rust:disallow-unwrap-expect");

impl Rule for DisallowUnwrapExpectRule {
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
        IssueType::CodeSmell
    }

    fn check(&self, file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        // Skip test files / test modules
        let path = file.path();
        if path.contains("tests/") || path.contains("_test.rs") {
            return Vec::new();
        }
        let test_ranges = vord_rules_engine::rust_test_module_ranges(file.content());

        let mut findings = Vec::new();

        fn walk(node: &AstNode, test_ranges: &[(u32, u32)], out: &mut Vec<Finding>) {
            // `call_expression` nodes are mapped to `NodeKind::Call` by the
            // Rust tree-sitter adapter (see parsers/treesitter-rust), never
            // left as `NodeKind::Other("call_expression")` — matching on the
            // latter meant this rule never fired on real code.
            if *node.kind() == NodeKind::Call {
                if let Some(field) = node.first_child() {
                    let text = field.text();
                    if (text.ends_with(".unwrap") || text.ends_with(".expect"))
                        && !vord_rules_engine::in_ranges(test_ranges, field.span().start_line)
                    {
                        out.push(Finding::new(
                            "Avoid `.unwrap()` or `.expect()` in production code as it causes panics. Propagate errors using `?` or handle them explicitly with `match`/`if let`.",
                            field.span(),
                        ));
                    }
                }
            }
            for child in node.children() {
                walk(child, test_ranges, out);
            }
        }

        walk(ast, &test_ranges, &mut findings);
        findings
    }
}

#[cfg(test)]
mod tests {
    use vord_rules_engine::AstParser;

    use super::*;

    fn check(code: &str) -> Vec<Finding> {
        let file = SourceFile::new("t.rs", code, LanguageIdentifier::rust()).unwrap();
        let ast = vord_parser_rust::RustParser::new().parse(&file).unwrap();
        DisallowUnwrapExpectRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_unwrap_in_production_code() {
        let findings = check("fn f() { let a = g().unwrap(); }\n");
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn flags_expect_in_production_code() {
        let findings = check("fn f() { let a = g().expect(\"reason\"); }\n");
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn ignores_unrelated_calls() {
        assert!(check("fn f() { let a = g().unwrap_or_default(); }\n").is_empty());
    }

    #[test]
    fn ignores_unwrap_inside_a_cfg_test_module() {
        let code = "fn prod() {}\n\n#[cfg(test)]\nmod tests {\n    #[test]\n    fn t() {\n        let a = g().unwrap();\n        let b = g().expect(\"reason\");\n    }\n}\n";
        assert!(check(code).is_empty());
    }
}
