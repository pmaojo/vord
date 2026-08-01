use yunq_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile, Span};
use yunq_rules_engine::{declare_rule_id, Finding, IssueType, Rule, RuleId, Severity};

declare_rule_id!(DisallowPanicMacrosRule, "rust:disallow-panic-macros");

impl Rule for DisallowPanicMacrosRule {
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

    fn remediation_effort_minutes(&self) -> u32 {
        5
    }

    fn metadata(&self) -> yunq_rules_engine::RuleMetadata {
        yunq_rules_engine::RuleMetadata {
            description: "`panic!`, `todo!`, `unimplemented!`, and `unreachable!` macros cause unrecoverable crashes in production code. Use `Result` and explicit error handling instead.".into(),
            tags: vec!["reliability".into(), "rust".into(), "error-handling".into()],
            cwe: None,
            produces_hotspots: false,
        }
    }

    fn check(&self, file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        let path = file.path();
        if path.contains("tests/")
            || path.contains("benches/")
            || path.contains("examples/")
            || path.ends_with("_test.rs")
            || path.ends_with("_tests.rs")
        {
            return Vec::new();
        }

        let mut findings = Vec::new();

        fn walk<'a>(node: &'a AstNode, in_test: bool, out: &mut Vec<Finding>) {
            let is_now_test = in_test || is_test_node(node);

            if !is_now_test {
                if let Some((macro_name, span)) = check_panic_macro(node) {
                    out.push(Finding::new(
                        format!(
                            "Avoid `{macro_name}` macro in production code; handle errors using `Result` instead"
                        ),
                        span,
                    ));
                }
            }

            let mut pending_test_attr = false;
            for child in node.children() {
                let child_kind = match child.kind() {
                    NodeKind::Other(k) => k.as_ref(),
                    _ => "",
                };
                if child_kind == "attribute_item" && child.text().contains("test") {
                    pending_test_attr = true;
                }

                let child_in_test = is_now_test || pending_test_attr;
                walk(child, child_in_test, out);

                if child_kind != "attribute_item" {
                    pending_test_attr = false;
                }
            }
        }

        walk(ast, false, &mut findings);
        findings
    }
}

fn is_test_node(node: &AstNode) -> bool {
    let kind_str = match node.kind() {
        NodeKind::Other(k) => k.as_ref(),
        _ => "",
    };
    if kind_str == "mod_item" {
        let text = node.text();
        if text.contains("#[cfg(test)]") || text.contains("mod tests") || text.contains("mod test")
        {
            return true;
        }
    } else if kind_str == "function_item" || *node.kind() == NodeKind::FunctionDef {
        let text = node.text();
        if text.contains("#[test]")
            || text.contains("#[tokio::test]")
            || text.contains("#[cfg(test)]")
            || text.contains("#[async_std::test]")
            || text.contains("#[test_case]")
        {
            return true;
        }
        if let Some(ident) = node.children().iter().find(|c| *c.kind() == NodeKind::Identifier) {
            if ident.text().starts_with("test_") || ident.text().starts_with("test") {
                return true;
            }
        }
    }
    false
}

fn check_panic_macro(node: &AstNode) -> Option<(&'static str, Span)> {
    let is_macro = matches!(node.kind(), NodeKind::Other(k) if k.as_ref() == "macro_invocation")
        || *node.kind() == NodeKind::Call;
    if !is_macro {
        return None;
    }

    let first = node.first_child()?;
    let name = first.text().trim_end_matches('!');
    let name = name.rsplit("::").next().unwrap_or(name);

    let macro_name = match name {
        "panic" => "panic!",
        "todo" => "todo!",
        "unimplemented" => "unimplemented!",
        "unreachable" => "unreachable!",
        _ => return None,
    };

    Some((macro_name, node.span()))
}

#[cfg(test)]
mod tests {
    use yunq_ast::SourceFile;
    use yunq_rules_engine::AstParser;

    use super::*;

    fn check(code: &str) -> Vec<Finding> {
        check_with_path("src/lib.rs", code)
    }

    fn check_with_path(path: &str, code: &str) -> Vec<Finding> {
        let file = SourceFile::new(path, code, LanguageIdentifier::rust()).unwrap();
        let ast = yunq_parser_rust::RustParser::new().parse(&file).unwrap();
        DisallowPanicMacrosRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_panic_macro_in_prod_code() {
        let findings = check("fn process() { panic!(\"unexpected error\"); }\n");
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("panic!"));
    }

    #[test]
    fn flags_todo_macro_in_prod_code() {
        let findings = check("fn feature() { todo!(); }\n");
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("todo!"));
    }

    #[test]
    fn flags_unimplemented_macro_in_prod_code() {
        let findings = check("fn parse() { unimplemented!(); }\n");
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("unimplemented!"));
    }

    #[test]
    fn flags_unreachable_macro_in_prod_code() {
        let findings = check("fn state() { unreachable!(); }\n");
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("unreachable!"));
    }

    #[test]
    fn ignores_panic_macros_in_test_functions() {
        let findings = check("#[test]\nfn test_foo() { panic!(\"fail\"); }\n");
        assert!(findings.is_empty());
    }

    #[test]
    fn ignores_panic_macros_in_test_module() {
        let findings = check("#[cfg(test)]\nmod tests {\n    #[test]\n    fn t() { todo!(); }\n}\n");
        assert!(findings.is_empty());
    }

    #[test]
    fn ignores_panic_macros_in_test_files() {
        let findings = check_with_path("tests/integration_test.rs", "fn run() { panic!(\"err\"); }\n");
        assert!(findings.is_empty());
    }

    #[test]
    fn ignores_safe_macros() {
        let findings = check("fn log() { println!(\"hello\"); format!(\"x\"); }\n");
        assert!(findings.is_empty());
    }
}
