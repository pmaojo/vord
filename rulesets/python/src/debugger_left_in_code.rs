//! Rule: flags `pdb.set_trace()` / `breakpoint()`. Either one suspends
//! the process waiting on stdin the moment that line executes; left in
//! by accident, it hangs the first request or job that reaches it in any
//! non-interactive environment (a server, a CI job, a worker).

use yunq_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use yunq_rules_engine::{Finding, IssueType, Rule, RuleId, Severity};

fn is_debugger_call(call: &AstNode) -> bool {
    call.first_child().is_some_and(|callee| {
        callee.text() == "pdb.set_trace"
            || callee.text() == "ipdb.set_trace"
            || (callee.kind() == &NodeKind::Identifier && callee.text() == "breakpoint")
    })
}

pub struct DebuggerLeftInCodeRule {
    id: RuleId,
}

impl DebuggerLeftInCodeRule {
    pub fn new() -> Self {
        Self {
            id: RuleId::new("python:debugger-left-in-code").expect("valid rule id"),
        }
    }
}

impl Default for DebuggerLeftInCodeRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for DebuggerLeftInCodeRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn applies_to(&self, lang: &LanguageIdentifier) -> bool {
        *lang == LanguageIdentifier::python()
    }

    fn default_severity(&self) -> Severity {
        Severity::Major
    }

    fn issue_type(&self) -> IssueType {
        IssueType::Bug
    }

    fn remediation_effort_minutes(&self) -> u32 {
        2
    }

    fn metadata(&self) -> yunq_rules_engine::RuleMetadata {
        yunq_rules_engine::RuleMetadata {
            description: "pdb.set_trace()/breakpoint() suspends the process waiting on stdin; left in by accident it hangs the first request or job that reaches it in any non-interactive environment.".into(),
            tags: vec!["bug".into(), "cwe".into()],
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
            .filter(|call| is_debugger_call(call))
            .map(|call| Finding::new("debugger call left in code; it will hang the process on the first non-interactive run that reaches it", call.span()))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use yunq_rules_engine::AstParser;

    use super::*;

    fn findings(code: &str) -> Vec<Finding> {
        let file = SourceFile::new("t.py", code, LanguageIdentifier::python()).unwrap();
        let ast = yunq_parser_python::PythonParser::new()
            .parse(&file)
            .unwrap();
        DebuggerLeftInCodeRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_pdb_set_trace() {
        assert_eq!(findings("pdb.set_trace()\n").len(), 1);
    }

    #[test]
    fn flags_bare_breakpoint() {
        assert_eq!(findings("breakpoint()\n").len(), 1);
    }

    #[test]
    fn ignores_unrelated_calls() {
        assert!(findings("logging.debug('checkpoint')\n").is_empty());
    }
}
