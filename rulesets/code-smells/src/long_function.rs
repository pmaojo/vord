use vord_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use vord_rules_engine::{Finding, Rule, RuleId, Severity};

/// Default line threshold for non-JSX files.
const DEFAULT_MAX_LINES: u32 = 50;

/// Higher threshold for `.tsx`/`.jsx` files, where JSX markup makes
/// components naturally longer than logic-heavy functions.
const JSX_MAX_LINES: u32 = 80;

/// Flags functions longer than a configurable number of lines. Skips
/// `tests/*.rs` integration test files — a single long, sequential,
/// assertion-heavy end-to-end test sharing one expensive setup is often
/// clearer than splitting it just to satisfy a line count.
///
/// JSX/TSX files and functions whose body is primarily JSX markup get a
/// higher threshold (`JSX_MAX_LINES` instead of `DEFAULT_MAX_LINES`) — a
/// 60-line component returning clean markup is normal frontend code, not a
/// smell.
pub struct LongFunctionRule {
    id: RuleId,
    max_lines: u32,
}

impl LongFunctionRule {
    pub fn new(max_lines: u32) -> Self {
        Self {
            id: RuleId::new("smells:long-function").expect("valid rule id"),
            max_lines,
        }
    }
}

impl Default for LongFunctionRule {
    fn default() -> Self {
        Self::new(DEFAULT_MAX_LINES)
    }
}

impl Rule for LongFunctionRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn applies_to(&self, _language: &LanguageIdentifier) -> bool {
        true
    }

    fn default_severity(&self) -> Severity {
        Severity::Minor
    }

    fn check(&self, file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        if vord_rules_engine::is_test_only_path(file.path()) {
            return Vec::new();
        }
        let file_is_jsx = file.path().ends_with(".tsx") || file.path().ends_with(".jsx");
        ast.descendants()
            .filter(|n| *n.kind() == NodeKind::FunctionDef)
            .filter(|f| {
                let threshold = if file_is_jsx || function_body_is_primarily_jsx(f) {
                    JSX_MAX_LINES
                } else {
                    self.max_lines
                };
                f.span().line_count() > threshold
            })
            .map(|f| {
                let threshold = if file_is_jsx || function_body_is_primarily_jsx(f) {
                    JSX_MAX_LINES
                } else {
                    self.max_lines
                };
                Finding::new(
                    format!(
                        "function spans {} lines (max {})",
                        f.span().line_count(),
                        threshold
                    ),
                    f.span(),
                )
            })
            .collect()
    }
}

/// Returns `true` when a function's body is primarily JSX markup — a
/// single `return` statement whose expression is a JSX element or fragment.
/// Such functions are naturally verbose because JSX is verbose, not because
/// the logic is complex.
fn function_body_is_primarily_jsx(func: &AstNode) -> bool {
    let Some(body) = func.children().last() else {
        return false;
    };
    let statements: Vec<&AstNode> = body.children().iter().filter(|c| is_statement(c)).collect();
    // A JSX component typically has a single return statement.
    if statements.len() != 1 {
        return false;
    }
    let stmt = statements[0];
    is_return_of_jsx(stmt)
}

/// A `return_statement` whose expression is a JSX element, self-closing
/// element, fragment, or a parenthesized JSX expression.
fn is_return_of_jsx(stmt: &AstNode) -> bool {
    if !matches!(stmt.kind(), NodeKind::Other(k) if k.as_ref() == "return_statement") {
        return false;
    }
    stmt.children()
        .iter()
        .any(|expr| is_jsx_node(expr) || is_parenthesized_jsx(expr))
}

fn is_jsx_node(node: &AstNode) -> bool {
    matches!(
        node.kind(),
        NodeKind::Other(k) if matches!(k.as_ref(), "jsx_element" | "jsx_self_closing_element" | "jsx_fragment")
    )
}

fn is_parenthesized_jsx(node: &AstNode) -> bool {
    if !matches!(node.kind(), NodeKind::Other(k) if k.as_ref() == "parenthesized_expression") {
        return false;
    }
    node.children().first().is_some_and(is_jsx_node)
}

fn is_statement(node: &AstNode) -> bool {
    matches!(node.kind(), NodeKind::Other(k) if is_statement_kind(k.as_ref()))
}

fn is_statement_kind(kind: &str) -> bool {
    kind == "return_statement"
        || kind == "expression_statement"
        || kind == "variable_declaration"
        || kind == "if_statement"
        || kind == "for_statement"
        || kind == "for_in_statement"
        || kind == "while_statement"
}

#[cfg(test)]
mod tests {
    use vord_ast::SourceFile;
    use vord_rules_engine::AstParser;

    use super::*;

    #[test]
    fn flags_functions_over_threshold() {
        let body: String = (0..10).map(|i| format!("    let x{i} = {i};\n")).collect();
        let code = format!("fn long() {{\n{body}}}\n\nfn short() {{}}\n");
        let file = SourceFile::new("t.rs", code, LanguageIdentifier::rust()).unwrap();
        let ast = vord_parser_rust::RustParser::new().parse(&file).unwrap();

        let findings = LongFunctionRule::new(5).check(&file, &ast);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("12 lines"));
    }

    #[test]
    fn ignores_long_functions_in_integration_test_files() {
        let body: String = (0..10).map(|i| format!("    let x{i} = {i};\n")).collect();
        let code = format!("fn long() {{\n{body}}}\n");
        let file = SourceFile::new("tests/e2e.rs", code, LanguageIdentifier::rust()).unwrap();
        let ast = vord_parser_rust::RustParser::new().parse(&file).unwrap();

        assert!(LongFunctionRule::new(5).check(&file, &ast).is_empty());
    }

    #[test]
    fn allows_jsx_component_below_jsx_threshold() {
        // A 60-line component returning JSX should pass under the 80-line JSX threshold.
        let body_lines: Vec<String> = (0..58)
            .map(|i| format!("  <div key={i}>content</div>"))
            .collect();
        let body = body_lines.join("\n");
        let code = format!("function Comp() {{\n  return (\n{body}\n  );\n}}\n");
        let file = SourceFile::new("Comp.tsx", code, LanguageIdentifier::typescript()).unwrap();
        let ast = vord_parser_typescript::TypeScriptParser::new()
            .parse(&file)
            .unwrap();

        let findings = LongFunctionRule::new(DEFAULT_MAX_LINES).check(&file, &ast);
        assert!(
            findings.is_empty(),
            "JSX component at ~60 lines should not flag: {findings:?}"
        );
    }

    #[test]
    fn flags_non_jsx_function_at_standard_threshold() {
        // A 55-line non-JSX function in a .ts file should still flag at 50 lines.
        let body: String = (0..53).map(|i| format!("  const x{i} = {i};\n")).collect();
        let code = format!("function compute() {{\n{body}}}\n");
        let file = SourceFile::new("t.ts", code, LanguageIdentifier::typescript()).unwrap();
        let ast = vord_parser_typescript::TypeScriptParser::new()
            .parse(&file)
            .unwrap();

        let findings = LongFunctionRule::new(DEFAULT_MAX_LINES).check(&file, &ast);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn jsx_return_detection_finds_jsx_element() {
        let code = "function Comp() {\n  return <div>hello</div>;\n}\n";
        let file = SourceFile::new("t.tsx", code, LanguageIdentifier::typescript()).unwrap();
        let ast = vord_parser_typescript::TypeScriptParser::new()
            .parse(&file)
            .unwrap();
        let func = ast
            .descendants()
            .find(|n| *n.kind() == NodeKind::FunctionDef)
            .unwrap();
        assert!(function_body_is_primarily_jsx(func));
    }

    #[test]
    fn non_jsx_return_not_detected() {
        let code = "function compute() {\n  return 42;\n}\n";
        let file = SourceFile::new("t.ts", code, LanguageIdentifier::typescript()).unwrap();
        let ast = vord_parser_typescript::TypeScriptParser::new()
            .parse(&file)
            .unwrap();
        let func = ast
            .descendants()
            .find(|n| *n.kind() == NodeKind::FunctionDef)
            .unwrap();
        assert!(!function_body_is_primarily_jsx(func));
    }
}
