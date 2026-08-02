//! Rule: a functional "god module" — a file exporting an excessive number
//! of top-level functions, the functional-paradigm analogue of
//! `smells:god-class` (which only fires on `class`/`struct` declarations and
//! so stays silent on classless TypeScript/JavaScript modules, Python
//! modules, Go packages and Rust files).
//!
//! SOLID/DDD checks in this codebase mostly key off `ClassRegistry`
//! (`core/symbols`), which models classes/structs/interfaces; purely
//! functional code — exported functions, closures, module-level
//! definitions — never activates them. This rule closes that gap by
//! treating *top-level functions* as the module's units: too many unrelated
//! ones in a single file means the file has more than one responsibility.

use vord_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use vord_rules_engine::{Finding, IssueType, Rule, RuleId, Severity};

pub struct FunctionalModuleRule {
    id: RuleId,
    max_exported_functions: usize,
}

impl FunctionalModuleRule {
    pub fn new(max_exported_functions: usize) -> Self {
        Self {
            id: RuleId::new("architecture:functional-module").expect("valid rule id"),
            max_exported_functions,
        }
    }
}

impl Default for FunctionalModuleRule {
    /// Mirrors `smells:god-class`'s method threshold (20) with a little
    /// headroom for modules that legitimately group small pure helpers.
    fn default() -> Self {
        Self::new(25)
    }
}

/// A function-like node in the neutral AST: mapped `FunctionDef`, or a
/// raw grammar kind (`function_item` Rust, `function_declaration` Go/TS,
/// `function_definition` Python) preserved as `Other`.
fn is_function_kind(node: &AstNode) -> bool {
    matches!(node.kind(), NodeKind::FunctionDef)
        || matches!(
            node.kind(),
            NodeKind::Other(k)
                if matches!(
                    k.as_ref(),
                    "function_item" | "function_declaration" | "function_definition"
                )
        )
}

/// An arrow/`function` expression assigned to a module-level variable —
/// `export const handler = () => ...` / `export const handler = function ...`.
/// Prefers the precise signal (an arrow/function expression is itself a
/// `FunctionDef` in the neutral AST) and only falls back to text when the
/// parser kept the arrow as an unnamed kind.
fn is_arrow_export(node: &AstNode) -> bool {
    node.descendants().any(|d| *d.kind() == NodeKind::FunctionDef)
        || node.text().contains("=>")
}

/// Counts a file's top-level functional units. Class-based files are left
/// to `smells:god-class`, so a file declaring a class with methods is not
/// double-counted here — its `class_declaration` is not a function kind and
/// its methods are not top-level children.
fn count_top_level_functions(path: &str, ast: &AstNode) -> usize {
    if path.ends_with(".rs") || path.ends_with(".go") {
        // Rust/Go: every top-level function is a module-level unit.
        return ast
            .children()
            .iter()
            .filter(|child| is_function_kind(child))
            .count();
    }
    // TS/JS/Python: top-level functions, plus `export`-wrapped ones (the
    // neutral AST keeps `export_statement` as a wrapper node).
    ast.children()
        .iter()
        .map(|child| {
            if is_function_kind(child) {
                1
            } else if matches!(child.kind(), NodeKind::Other(k) if k.as_ref() == "export_statement")
            {
                child
                    .children()
                    .iter()
                    .filter(|inner| is_function_kind(inner) || is_arrow_export(inner))
                    .count()
            } else {
                0
            }
        })
        .sum()
}

impl Rule for FunctionalModuleRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn applies_to(&self, language: &LanguageIdentifier) -> bool {
        // Scoped to the languages with first-class module-level functions,
        // matching the SOLID/DDD gatekeeper's four-language table — Java's
        // "one public class per file" and PHP's top-level-function idiom are
        // different shapes, and firing here would be noise for them.
        matches!(
            language.as_str(),
            "typescript" | "python" | "rust" | "go"
        )
    }

    fn default_severity(&self) -> Severity {
        Severity::Major
    }

    fn issue_type(&self) -> IssueType {
        IssueType::CodeSmell
    }

    fn check(&self, file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        if vord_rules_engine::is_test_only_path(file.path()) {
            return Vec::new();
        }
        let count = count_top_level_functions(file.path(), ast);
        if count <= self.max_exported_functions {
            return Vec::new();
        }
        vec![Finding::new(
            format!(
                "Functional god module: `{}` exposes {count} top-level functions (max {}) — the classless analogue of a god class. Split it along its responsibilities into focused modules.",
                file.path(),
                self.max_exported_functions
            ),
            ast.span(),
        )]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vord_parser_typescript::TypeScriptParser;
    use vord_rules_engine::AstParser;

    fn check_ts(code: &str, max: usize) -> Vec<Finding> {
        let file = SourceFile::new(
            "module.ts",
            code,
            LanguageIdentifier::typescript(),
        )
        .unwrap();
        let ast = TypeScriptParser::new().parse(&file).unwrap();
        FunctionalModuleRule::new(max).check(&file, &ast)
    }

    #[test]
    fn flags_a_module_exporting_too_many_functions() {
        let mut code = String::new();
        for i in 0..30 {
            code.push_str(&format!("export function fn{i}() {{ return {i}; }}\n"));
        }
        let findings = check_ts(&code, 25);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("30 top-level functions"));
    }

    #[test]
    fn counts_exported_arrow_consts_as_units() {
        let mut code = String::new();
        for i in 0..30 {
            code.push_str(&format!("export const fn{i} = () => {i};\n"));
        }
        let findings = check_ts(&code, 25);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn a_small_module_stays_silent() {
        let code = "export function add(a: number, b: number) { return a + b; }\nexport function sub(a: number, b: number) { return a - b; }\n";
        let findings = check_ts(code, 25);
        assert!(findings.is_empty());
    }

    #[test]
    fn a_class_with_many_methods_is_not_a_functional_module() {
        // Methods live inside the class, not at top level — god-class's
        // territory, not this rule's.
        let mut code = String::new();
        code.push_str("class Service {\n");
        for i in 0..40 {
            code.push_str(&format!("  m{i}() {{}}\n"));
        }
        code.push_str("}\n");
        let findings = check_ts(&code, 25);
        assert!(findings.is_empty());
    }

    #[test]
    fn flags_a_rust_file_with_too_many_top_level_functions() {
        use vord_parser_rust::RustParser;
        let mut code = String::new();
        for i in 0..30 {
            code.push_str(&format!("pub fn fn{i}() -> i32 {{ {i} }}\n"));
        }
        let file = SourceFile::new("module.rs", code, LanguageIdentifier::rust()).unwrap();
        let ast = RustParser::new().parse(&file).unwrap();
        let findings = FunctionalModuleRule::new(25).check(&file, &ast);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn flags_a_python_module_with_too_many_top_level_functions() {
        use vord_parser_python::PythonParser;
        let mut code = String::new();
        for i in 0..30 {
            code.push_str(&format!("def fn{i}():\n    return {i}\n"));
        }
        let file = SourceFile::new("module.py", code, LanguageIdentifier::python()).unwrap();
        let ast = PythonParser::new().parse(&file).unwrap();
        let findings = FunctionalModuleRule::new(25).check(&file, &ast);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn silent_in_test_only_paths() {
        use vord_parser_python::PythonParser;
        let mut code = String::new();
        for i in 0..40 {
            code.push_str(&format!("def test_fn{i}():\n    assert {i} == {i}\n"));
        }
        let file = SourceFile::new("tests/test_basic.py", code, LanguageIdentifier::python()).unwrap();
        let ast = PythonParser::new().parse(&file).unwrap();
        let findings = FunctionalModuleRule::new(25).check(&file, &ast);
        assert!(findings.is_empty());
    }
}
