//! Rule: flags a function declared `async` whose body contains no `await`
//! expression. Marking a function `async` when it never awaits anything
//! still wraps its return value in a `Promise` and adds a microtask tick,
//! with no benefit — mirrors ESLint's `require-await`.

use vord_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use vord_rules_engine::{Finding, IssueType, Rule, RuleId, RuleMetadata, Severity};

use crate::common::is_other;

fn is_async(func: &AstNode) -> bool {
    func.text().trim_start().starts_with("async")
}

fn has_await(func: &AstNode) -> bool {
    func.descendants().any(|n| is_other(n, "await_expression"))
}

fn flagged(node: &AstNode) -> bool {
    *node.kind() == NodeKind::FunctionDef && is_async(node) && !has_await(node)
}

pub struct AsyncFunctionWithoutAwaitRule {
    id: RuleId,
}

impl AsyncFunctionWithoutAwaitRule {
    pub fn new() -> Self {
        Self {
            id: RuleId::new("typescript:async-function-without-await").expect("valid rule id"),
        }
    }
}

impl Default for AsyncFunctionWithoutAwaitRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for AsyncFunctionWithoutAwaitRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn applies_to(&self, lang: &LanguageIdentifier) -> bool {
        *lang == LanguageIdentifier::typescript()
    }

    fn default_severity(&self) -> Severity {
        Severity::Minor
    }

    fn issue_type(&self) -> IssueType {
        IssueType::CodeSmell
    }

    fn remediation_effort_minutes(&self) -> u32 {
        3
    }

    fn metadata(&self) -> RuleMetadata {
        RuleMetadata {
            description: "This function is declared `async` but its body never uses `await`. Remove `async` (it just adds an unnecessary microtask tick and Promise wrapper), or use the `await` the function was meant to have.".into(),
            tags: vec!["typescript".into(), "clarity".into(), "promise".into()],
            cwe: None,
            produces_hotspots: false,
        }
    }

    fn check(&self, _file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        ast.descendants()
            .filter(|n| flagged(n))
            .map(|n| {
                Finding::new(
                    "this `async` function never uses `await`; drop `async` or add the missing `await`",
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
        AsyncFunctionWithoutAwaitRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_async_function_declaration_without_await() {
        let findings = check("async function load() {\n  return fetchThing();\n}\n");
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn flags_async_arrow_without_await() {
        assert_eq!(check("const load = async () => {\n  return 1;\n};\n").len(), 1);
    }

    #[test]
    fn flags_async_method_without_await() {
        let findings = check("class C {\n  async load() {\n    return 1;\n  }\n}\n");
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn allows_async_function_with_await() {
        assert!(check("async function load() {\n  return await fetchThing();\n}\n").is_empty());
    }

    #[test]
    fn allows_non_async_function() {
        assert!(check("function load() {\n  return fetchThing();\n}\n").is_empty());
    }

    #[test]
    fn allows_async_function_awaiting_in_nested_expression() {
        assert!(check("async function f() {\n  const x = [await g()];\n  return x;\n}\n").is_empty());
    }
}
