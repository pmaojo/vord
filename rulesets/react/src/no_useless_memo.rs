//! Rule: flags `useMemo` or `useCallback` used on primitive literal values
//! (strings, numbers, booleans, null, undefined) or empty arrays/objects.

use yunq_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use yunq_rules_engine::{declare_rule_id, Finding, IssueType, Rule, RuleId, RuleMetadata, Severity};

use crate::common::{call_arguments, callee_name, is_other};

declare_rule_id!(NoUselessMemoRule, "react:no-useless-memo");

impl Rule for NoUselessMemoRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn applies_to(&self, language: &LanguageIdentifier) -> bool {
        language.is_typescript() || language.is_javascript()
    }

    fn default_severity(&self) -> Severity {
        Severity::Minor
    }

    fn issue_type(&self) -> IssueType {
        IssueType::CodeSmell
    }

    fn metadata(&self) -> RuleMetadata {
        RuleMetadata {
            description: "Using `useMemo` or `useCallback` on primitive literals or empty array/object literals is unnecessary and adds overhead.".into(),
            tags: vec!["react".into(), "performance".into(), "useless-memo".into()],
            cwe: None,
            produces_hotspots: false,
        }
    }

    fn check(&self, _file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        let mut findings = Vec::new();

        for node in ast.descendants() {
            if *node.kind() != NodeKind::Call {
                continue;
            }

            let Some(name) = callee_name(node) else {
                continue;
            };

            if name != "useMemo" && name != "useCallback" {
                continue;
            }

            let args = call_arguments(node);
            let Some(first_arg) = args.first() else {
                continue;
            };

            if is_useless_memo_arg(first_arg) {
                findings.push(Finding::new(
                    format!("Avoid using `{name}` on primitive literals or empty array/object literals."),
                    node.span(),
                ));
            }
        }

        findings
    }
}

fn unwrap_parentheses(mut node: &AstNode) -> &AstNode {
    while is_other(node, "parenthesized_expression") {
        if let Some(inner) = node.children().iter().find(|c| c.text() != "(" && c.text() != ")") {
            node = inner;
        } else {
            break;
        }
    }
    node
}

fn is_primitive_or_empty(node: &AstNode) -> bool {
    let node = unwrap_parentheses(node);
    let trimmed = node.text().trim();
    if trimmed == "[]"
        || trimmed == "{}"
        || trimmed == "true"
        || trimmed == "false"
        || trimmed == "null"
        || trimmed == "undefined"
    {
        return true;
    }

    match node.kind() {
        NodeKind::StringLiteral => true,
        NodeKind::Other(k) => match k.as_ref() {
            "string" | "number" | "true" | "false" | "null" | "undefined" => true,
            "template_string" => !node.text().contains("${"),
            "array" => node.text().split_whitespace().collect::<String>() == "[]",
            "object" => node.text().split_whitespace().collect::<String>() == "{}",
            _ => {
                (trimmed.starts_with('"') && trimmed.ends_with('"'))
                    || (trimmed.starts_with('\'') && trimmed.ends_with('\''))
                    || (!trimmed.is_empty() && trimmed.parse::<f64>().is_ok())
            }
        },
        _ => {
            (trimmed.starts_with('"') && trimmed.ends_with('"'))
                || (trimmed.starts_with('\'') && trimmed.ends_with('\''))
                || (!trimmed.is_empty() && trimmed.parse::<f64>().is_ok())
        }
    }
}

fn is_useless_memo_arg(node: &AstNode) -> bool {
    let unwrapped = unwrap_parentheses(node);

    if is_primitive_or_empty(unwrapped) {
        return true;
    }

    if *unwrapped.kind() == NodeKind::FunctionDef
        || is_other(unwrapped, "arrow_function")
        || is_other(unwrapped, "function_expression")
    {
        // Check function return value or body expression
        let children = unwrapped.children();
        if let Some(block) = children.iter().find(|c| is_other(c, "statement_block")) {
            for child in block.descendants() {
                if is_other(child, "return_statement") {
                    if let Some(ret_val) = child.children().iter().find(|c| c.text() != "return" && c.text() != ";") {
                        if is_primitive_or_empty(ret_val) {
                            return true;
                        }
                    }
                }
            }
        } else {
            // Concise arrow function body: find body expression (after `=>` or parameters)
            if let Some(body) = children.iter().find(|c| !is_other(c, "formal_parameters") && c.text() != "=>" && c.text() != "async") {
                if is_primitive_or_empty(body) {
                    return true;
                }
            }
        }
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use yunq_rules_engine::AstParser;

    fn check(code: &str) -> Vec<Finding> {
        let file = SourceFile::new("t.tsx", code, LanguageIdentifier::typescript()).unwrap();
        let ast = yunq_parser_typescript::TypeScriptParser::new()
            .parse(&file)
            .unwrap();
        NoUselessMemoRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_use_memo_returning_primitive_literal() {
        let findings = check("const val = useMemo(() => 42, []);\n");
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("useMemo"));
    }

    #[test]
    fn flags_use_memo_returning_string_literal() {
        let findings = check("const str = useMemo(() => 'hello', []);\n");
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn flags_use_memo_returning_empty_array() {
        let findings = check("const arr = useMemo(() => [], []);\n");
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn flags_use_memo_returning_empty_object() {
        let findings = check("const obj = useMemo(() => ({}), []);\n");
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn flags_use_callback_on_primitive_directly() {
        let findings = check("const cb = useCallback('hello', []);\n");
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn allows_valid_use_memo_and_use_callback() {
        let findings = check("const val = useMemo(() => computeHeavyThing(x), [x]);\nconst cb = useCallback(() => handleClick(id), [id]);\n");
        assert!(findings.is_empty());
    }

    #[test]
    fn allows_non_empty_array_and_object() {
        let findings = check("const arr = useMemo(() => [1, 2, 3], []);\nconst obj = useMemo(() => ({ a: 1 }), []);\n");
        assert!(findings.is_empty());
    }
}
