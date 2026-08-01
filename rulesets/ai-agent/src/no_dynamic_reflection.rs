use yunq_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use yunq_rules_engine::{declare_rule_id, Finding, IssueType, Rule, RuleId, Severity};

declare_rule_id!(NoDynamicReflectionRule, "ai-agent:no-dynamic-reflection");

impl Rule for NoDynamicReflectionRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn applies_to(&self, language: &LanguageIdentifier) -> bool {
        *language == LanguageIdentifier::python() || *language == LanguageIdentifier::typescript()
    }

    fn default_severity(&self) -> Severity {
        Severity::Major
    }

    fn issue_type(&self) -> IssueType {
        IssueType::Vulnerability
    }

    fn remediation_effort_minutes(&self) -> u32 {
        15
    }

    fn metadata(&self) -> yunq_rules_engine::RuleMetadata {
        yunq_rules_engine::RuleMetadata {
            description: "Dynamic reflection (`eval`, `exec`, `getattr(obj, var)`) with unchecked string variables allows prompt injection or untrusted data to execute arbitrary code or access internal object state.".into(),
            tags: vec!["security".into(), "ai-agent".into(), "reflection".into(), "injection".into()],
            cwe: Some(95),
            produces_hotspots: false,
        }
    }

    fn check(&self, _file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        let mut findings = Vec::new();

        fn walk<'a>(node: &'a AstNode, out: &mut Vec<Finding>) {
            let is_call = *node.kind() == NodeKind::Call
                || matches!(node.kind(), NodeKind::Other(k) if k.as_ref() == "call" || k.as_ref() == "call_expression");

            if is_call {
                if let Some(finding) = check_reflection_call(node) {
                    out.push(finding);
                }
            }

            for child in node.children() {
                walk(child, out);
            }
        }

        walk(ast, &mut findings);
        findings
    }
}

fn check_reflection_call(call_node: &AstNode) -> Option<Finding> {
    let callee = call_node.first_child()?;
    let callee_text = callee.text().trim();

    let args = extract_args(call_node);

    if callee_text == "eval" || callee_text == "exec" {
        let arg0 = args.first()?;
        if !is_string_literal(arg0) {
            return Some(Finding::new(
                format!(
                    "Avoid dynamic reflection/execution via `{callee_text}` with unchecked variable `{}`. Use explicit function calls or structured dispatches.",
                    arg0.text()
                ),
                call_node.span(),
            ));
        }
    } else if callee_text == "getattr" || callee_text == "setattr" || callee_text == "delattr" {
        let arg1 = args.get(1)?;
        if !is_string_literal(arg1) {
            return Some(Finding::new(
                format!(
                    "Avoid dynamic reflection via `{callee_text}` with unchecked attribute variable `{}`. Use explicit property access or allowlists.",
                    arg1.text()
                ),
                call_node.span(),
            ));
        }
    } else if callee_text == "Reflect.get" || callee_text == "Reflect.set" || callee_text == "Reflect.has" {
        let arg1 = args.get(1)?;
        if !is_string_literal(arg1) {
            return Some(Finding::new(
                format!(
                    "Avoid dynamic reflection via `{callee_text}` with unchecked property variable `{}`. Use explicit property access or allowlists.",
                    arg1.text()
                ),
                call_node.span(),
            ));
        }
    }

    None
}

fn extract_args<'a>(call_node: &'a AstNode) -> Vec<&'a AstNode> {
    let mut args = Vec::new();
    for child in call_node.children().iter().skip(1) {
        let kind_str = match child.kind() {
            NodeKind::Other(k) => k.as_ref(),
            _ => "",
        };
        if kind_str == "argument_list" || kind_str == "arguments" {
            for arg_child in child.children() {
                let ak = match arg_child.kind() {
                    NodeKind::Other(k) => k.as_ref(),
                    _ => "",
                };
                if ak != "(" && ak != ")" && ak != "," {
                    args.push(arg_child);
                }
            }
        } else if kind_str != "(" && kind_str != ")" && kind_str != "," {
            args.push(child);
        }
    }
    args
}

fn is_string_literal(node: &AstNode) -> bool {
    if *node.kind() == NodeKind::StringLiteral {
        return true;
    }
    let text = node.text().trim();
    (text.starts_with('"') && text.ends_with('"'))
        || (text.starts_with('\'') && text.ends_with('\''))
        || (text.starts_with('`') && text.ends_with('`'))
}

#[cfg(test)]
mod tests {
    use yunq_ast::SourceFile;
    use yunq_rules_engine::AstParser;

    use super::*;

    fn check_py(code: &str) -> Vec<Finding> {
        let file = SourceFile::new("t.py", code, LanguageIdentifier::python()).unwrap();
        let ast = yunq_parser_python::PythonParser::new()
            .parse(&file)
            .unwrap();
        NoDynamicReflectionRule::new().check(&file, &ast)
    }

    fn check_ts(code: &str) -> Vec<Finding> {
        let file = SourceFile::new("t.ts", code, LanguageIdentifier::typescript()).unwrap();
        let ast = yunq_parser_typescript::TypeScriptParser::new()
            .parse(&file)
            .unwrap();
        NoDynamicReflectionRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_getattr_with_variable_python() {
        let findings = check_py("attr = get_user_attr()\nval = getattr(obj, attr)\n");
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("getattr"));
    }

    #[test]
    fn allows_getattr_with_literal_python() {
        let findings = check_py("val = getattr(obj, \"name\", None)\n");
        assert!(findings.is_empty());
    }

    #[test]
    fn flags_eval_with_variable_python() {
        let findings = check_py("user_input = input()\neval(user_input)\n");
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("eval"));
    }

    #[test]
    fn allows_eval_with_literal_python() {
        let findings = check_py("eval(\"1 + 1\")\n");
        assert!(findings.is_empty());
    }

    #[test]
    fn flags_exec_with_variable_python() {
        let findings = check_py("code_str = get_code()\nexec(code_str)\n");
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("exec"));
    }

    #[test]
    fn flags_reflect_get_with_variable_typescript() {
        let findings = check_ts("const prop = getProp();\nconst val = Reflect.get(obj, prop);\n");
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("Reflect.get"));
    }

    #[test]
    fn allows_reflect_get_with_literal_typescript() {
        let findings = check_ts("const val = Reflect.get(obj, \"prop\");\n");
        assert!(findings.is_empty());
    }
}
