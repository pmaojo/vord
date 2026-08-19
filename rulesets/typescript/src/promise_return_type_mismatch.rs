//! Rule: flags an `async` function whose explicit return type annotation
//! does not mention `Promise`. An `async` function always returns a
//! `Promise` at runtime regardless of what its return type says — so an
//! annotation like `async function f(): number` describes a type the
//! function can never actually produce, and any caller trusting that
//! annotation (e.g. using the value without `await`) is working from a
//! wrong contract.

use vord_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use vord_rules_engine::{Finding, IssueType, Rule, RuleId, RuleMetadata, Severity};

use crate::common::{is_generator, is_other};

fn is_async(func: &AstNode) -> bool {
    func.text().trim_start().starts_with("async")
}

fn return_type_annotation(func: &AstNode) -> Option<&AstNode> {
    func.children().iter().find(|c| is_other(c, "type_annotation"))
}

fn flagged(func: &AstNode) -> Option<&AstNode> {
    // `async function*` generators really do return `AsyncGenerator<T>` /
    // `AsyncIterableIterator<T>`, never `Promise<T>` — this rule's premise
    // ("an `async` function always returns a `Promise` at runtime") simply
    // doesn't hold for generators, so they're excluded to avoid flagging a
    // correct annotation as a mismatch.
    if *func.kind() != NodeKind::FunctionDef || !is_async(func) || is_generator(func) {
        return None;
    }
    let annotation = return_type_annotation(func)?;
    (!annotation.text().contains("Promise")).then_some(annotation)
}

pub struct PromiseReturnTypeMismatchRule {
    id: RuleId,
}

impl PromiseReturnTypeMismatchRule {
    pub fn new() -> Self {
        Self {
            id: RuleId::new("typescript:promise-return-type-mismatch").expect("valid rule id"),
        }
    }
}

impl Default for PromiseReturnTypeMismatchRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for PromiseReturnTypeMismatchRule {
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
        IssueType::Bug
    }

    fn remediation_effort_minutes(&self) -> u32 {
        5
    }

    fn metadata(&self) -> RuleMetadata {
        RuleMetadata {
            description: "This `async` function's return type annotation does not mention `Promise`, but an `async` function always returns a `Promise` at runtime. Wrap the annotation in `Promise<...>` to match what the function actually returns.".into(),
            tags: vec!["typescript".into(), "type-safety".into(), "promise".into()],
            cwe: None,
            produces_hotspots: false,
        }
    }

    fn check(&self, _file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        ast.descendants()
            .filter_map(flagged)
            .map(|n| {
                Finding::new(
                    "this `async` function's return type does not mention `Promise`, but it always returns one at runtime; wrap it in `Promise<...>`",
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
        PromiseReturnTypeMismatchRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_async_function_annotated_with_non_promise_type() {
        assert_eq!(check("async function f(): number {\n  return 1;\n}\n").len(), 1);
    }

    #[test]
    fn flags_async_arrow_annotated_with_non_promise_type() {
        assert_eq!(check("const f = async (): number => 1;\n").len(), 1);
    }

    #[test]
    fn allows_async_function_annotated_with_promise() {
        assert!(check("async function f(): Promise<number> {\n  return 1;\n}\n").is_empty());
    }

    #[test]
    fn allows_async_function_with_no_return_type_annotation() {
        assert!(check("async function f() {\n  return 1;\n}\n").is_empty());
    }

    #[test]
    fn allows_non_async_function_annotated_with_non_promise_type() {
        assert!(check("function f(): number {\n  return 1;\n}\n").is_empty());
    }

    /// Regression: `async function*` generators really do return
    /// `AsyncGenerator<T>`/`AsyncIterableIterator<T>` at runtime, not a
    /// `Promise` — this must not be flagged as a mismatch.
    #[test]
    fn allows_async_generator_annotated_with_async_generator_type() {
        let code = "async function* gen(): AsyncGenerator<number> {\n  yield 1;\n}\n";
        assert!(check(code).is_empty());
    }

    #[test]
    fn allows_async_generator_annotated_with_async_iterable_iterator_type() {
        let code = "async function* gen(): AsyncIterableIterator<number> {\n  yield 1;\n}\n";
        assert!(check(code).is_empty());
    }
}
