//! Rule: flags `console.log`/`console.debug` calls and `debugger` statements
//! — debugging aids that are easy to leave behind after a debugging session
//! and have no place in production code: `console.log` leaks whatever it's
//! printing into logs/devtools, and a `debugger;` statement pauses
//! execution outright whenever devtools are attached.

use yunq_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use yunq_rules_engine::{Finding, IssueType, Rule, RuleId, RuleMetadata, Severity};

use crate::common::is_other;

fn finding_for(node: &AstNode) -> Option<Finding> {
    if is_other(node, "debugger_statement") {
        return Some(Finding::new("`debugger` statement left in code pauses execution whenever devtools are attached", node.span()));
    }
    if *node.kind() == NodeKind::Call {
        let callee = node.first_child()?;
        let name = callee.text();
        if name == "console.log" || name == "console.debug" {
            return Some(Finding::new(format!("`{name}` left in code; remove it or use a real logger"), node.span()));
        }
    }
    None
}

pub struct LeftoverDebugStatementRule {
    id: RuleId,
}

impl LeftoverDebugStatementRule {
    pub fn new() -> Self {
        Self { id: RuleId::new("typescript:leftover-debug-statement").expect("valid rule id") }
    }
}

impl Default for LeftoverDebugStatementRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for LeftoverDebugStatementRule {
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
        2
    }

    fn metadata(&self) -> RuleMetadata {
        RuleMetadata {
            description: "`console.log`/`console.debug` and `debugger` are debugging aids that should not reach production code.".into(),
            tags: vec!["typescript".into(), "debug".into()],
            cwe: None,
            produces_hotspots: false,
        }
    }

    fn check(&self, file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        if yunq_rules_engine::is_test_only_path(file.path()) {
            return Vec::new();
        }
        ast.descendants().filter_map(finding_for).collect()
    }
}

#[cfg(test)]
mod tests {
    use yunq_ast::SourceFile;
    use yunq_rules_engine::AstParser;

    use super::*;

    fn check(code: &str) -> Vec<Finding> {
        let file = SourceFile::new("t.ts", code, LanguageIdentifier::typescript()).unwrap();
        let ast = yunq_parser_typescript::TypeScriptParser::new().parse(&file).unwrap();
        LeftoverDebugStatementRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_console_log() {
        assert_eq!(check("console.log('x');\n").len(), 1);
    }

    #[test]
    fn flags_console_debug() {
        assert_eq!(check("console.debug('x');\n").len(), 1);
    }

    #[test]
    fn flags_debugger_statement() {
        assert_eq!(check("function f() {\n  debugger;\n}\n").len(), 1);
    }

    #[test]
    fn allows_console_warn_and_error() {
        assert!(check("console.warn('x');\nconsole.error('y');\n").is_empty());
    }

    #[test]
    fn ignores_test_only_paths() {
        let file = SourceFile::new("tests/app.ts", "console.log('x');\n", LanguageIdentifier::typescript()).unwrap();
        let ast = yunq_parser_typescript::TypeScriptParser::new().parse(&file).unwrap();
        assert!(LeftoverDebugStatementRule::new().check(&file, &ast).is_empty());
    }
}
