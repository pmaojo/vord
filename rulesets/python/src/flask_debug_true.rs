//! Rule: flags `app.run(debug=True)`. Flask's debug mode enables the
//! Werkzeug interactive debugger, which evaluates arbitrary Python
//! expressions submitted through the browser once it's reachable — if
//! this ships to production, any anonymous visitor who triggers an
//! unhandled exception gets remote code execution.

use yunq_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use yunq_rules_engine::{Finding, IssueType, Rule, RuleId, Severity};

fn other_kind_name(node: &AstNode) -> Option<&str> {
    match node.kind() {
        NodeKind::Other(name) => Some(name.as_ref()),
        _ => None,
    }
}

fn has_debug_true_argument(call: &AstNode) -> bool {
    let Some(args) = call.children().iter().find(|c| other_kind_name(c) == Some("argument_list")) else { return false };
    args.children().iter().any(|arg| {
        other_kind_name(arg) == Some("keyword_argument")
            && arg.children().first().is_some_and(|name| name.text() == "debug")
            && arg.children().get(1).is_some_and(|value| other_kind_name(value) == Some("true"))
    })
}

pub struct FlaskDebugTrueRule {
    id: RuleId,
}

impl FlaskDebugTrueRule {
    pub fn new() -> Self {
        Self { id: RuleId::new("python:flask-debug-true").expect("valid rule id") }
    }
}

impl Default for FlaskDebugTrueRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for FlaskDebugTrueRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn applies_to(&self, lang: &LanguageIdentifier) -> bool {
        *lang == LanguageIdentifier::python()
    }

    fn default_severity(&self) -> Severity {
        Severity::Blocker
    }

    fn issue_type(&self) -> IssueType {
        IssueType::Vulnerability
    }

    fn remediation_effort_minutes(&self) -> u32 {
        5
    }

    fn metadata(&self) -> yunq_rules_engine::RuleMetadata {
        yunq_rules_engine::RuleMetadata {
            description: "Flask's debug mode enables the Werkzeug interactive debugger; if this reaches production, any visitor who triggers an unhandled exception can execute arbitrary Python.".into(),
            tags: vec!["security".into(), "cwe".into()],
            cwe: Some(489),
            produces_hotspots: false,
        }
    }

    fn check(&self, file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        if yunq_rules_engine::is_test_only_path(file.path()) {
            return Vec::new();
        }
        ast.descendants()
            .filter(|n| *n.kind() == NodeKind::Call)
            .filter(|call| call.first_child().is_some_and(|callee| callee.kind() == &NodeKind::MemberAccess && callee.text().ends_with(".run")))
            .filter(|call| has_debug_true_argument(call))
            .map(|call| Finding::new("debug=True enables the Werkzeug interactive debugger, which allows remote code execution if this ever runs in production", call.span()))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use yunq_rules_engine::AstParser;

    use super::*;

    fn findings(code: &str) -> Vec<Finding> {
        let file = SourceFile::new("t.py", code, LanguageIdentifier::python()).unwrap();
        let ast = yunq_parser_python::PythonParser::new().parse(&file).unwrap();
        FlaskDebugTrueRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_app_run_debug_true() {
        assert_eq!(findings("app.run(debug=True)\n").len(), 1);
    }

    #[test]
    fn allows_debug_false() {
        assert!(findings("app.run(debug=False)\n").is_empty());
    }

    #[test]
    fn allows_run_without_debug() {
        assert!(findings("app.run(host='127.0.0.1')\n").is_empty());
    }
}
