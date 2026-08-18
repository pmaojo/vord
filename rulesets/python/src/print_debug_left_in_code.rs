//! Rule: flags a bare `print(...)` call left in production code. `print`
//! writes straight to stdout with no level, no structured context, and no
//! way to route or silence it in production — a debugging leftover that
//! should be a `logging` call (or was never meant to ship). Calls inside
//! `if __name__ == "__main__":` guards are exempt: that's a legitimate
//! CLI entry point, not a forgotten debug statement.

use vord_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use vord_rules_engine::{Finding, IssueType, Rule, RuleId, Severity};

use crate::common::{is_test_file, other_kind_name};

fn is_main_guard_condition(cond: &AstNode) -> bool {
    other_kind_name(cond) == Some("comparison_operator")
        && cond.text().contains("__name__")
        && cond.text().contains("__main__")
}

fn is_bare_print_call(call: &AstNode) -> bool {
    call.first_child()
        .is_some_and(|callee| callee.kind() == &NodeKind::Identifier && callee.text() == "print")
}

fn walk(node: &AstNode, suppressed: bool, out: &mut Vec<Finding>) {
    if !suppressed && *node.kind() == NodeKind::Call && is_bare_print_call(node) {
        out.push(Finding::new(
            "print() left in code; use a logging call so output can be leveled, routed, and silenced in production",
            node.span(),
        ));
    }

    let main_guard_block = (other_kind_name(node) == Some("if_statement"))
        .then(|| node.children().first())
        .flatten()
        .filter(|cond| is_main_guard_condition(cond))
        .and_then(|_| node.children().get(1));

    for child in node.children() {
        let child_suppressed =
            suppressed || main_guard_block.is_some_and(|b| std::ptr::eq(b, child));
        walk(child, child_suppressed, out);
    }
}

pub struct PrintDebugLeftInCodeRule {
    id: RuleId,
}

impl PrintDebugLeftInCodeRule {
    pub fn new() -> Self {
        Self {
            id: RuleId::new("python:print-debug-left-in-code").expect("valid rule id"),
        }
    }
}

impl Default for PrintDebugLeftInCodeRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for PrintDebugLeftInCodeRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn applies_to(&self, lang: &LanguageIdentifier) -> bool {
        *lang == LanguageIdentifier::python()
    }

    fn default_severity(&self) -> Severity {
        Severity::Minor
    }

    fn issue_type(&self) -> IssueType {
        IssueType::CodeSmell
    }

    fn remediation_effort_minutes(&self) -> u32 {
        5
    }

    fn metadata(&self) -> vord_rules_engine::RuleMetadata {
        vord_rules_engine::RuleMetadata {
            description: "A bare print() call left in production code writes to stdout with no level, no structured context, and no way to route or silence it; use the logging module instead.".into(),
            tags: vec!["debug-code".into(), "maintainability".into()],
            cwe: None,
            produces_hotspots: false,
        }
    }

    fn check(&self, file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        if is_test_file(file.path()) {
            return Vec::new();
        }
        let mut out = Vec::new();
        walk(ast, false, &mut out);
        out
    }
}

#[cfg(test)]
mod tests {
    use vord_rules_engine::AstParser;

    use super::*;

    fn findings(code: &str) -> Vec<Finding> {
        let file = SourceFile::new("t.py", code, LanguageIdentifier::python()).unwrap();
        let ast = vord_parser_python::PythonParser::new()
            .parse(&file)
            .unwrap();
        PrintDebugLeftInCodeRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_bare_print() {
        assert_eq!(findings("def f():\n    print('x')\n").len(), 1);
    }

    #[test]
    fn allows_print_in_main_guard() {
        assert!(findings("if __name__ == '__main__':\n    print('hi')\n").is_empty());
    }

    #[test]
    fn ignores_test_files() {
        let file = SourceFile::new("tests/t.py", "print('x')\n", LanguageIdentifier::python()).unwrap();
        let ast = vord_parser_python::PythonParser::new()
            .parse(&file)
            .unwrap();
        assert!(PrintDebugLeftInCodeRule::new().check(&file, &ast).is_empty());
    }

    #[test]
    fn ignores_unrelated_calls() {
        assert!(findings("logging.info('x')\n").is_empty());
    }
}
