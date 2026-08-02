use vord_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use vord_rules_engine::{Finding, IssueType, Rule, RuleId, Severity};

/// Flags dynamic code execution: `eval(...)` / `new Function(...)` in
/// TypeScript, `eval(...)` / `exec(...)` in Python.
pub struct EvalUsageRule {
    id: RuleId,
}

impl EvalUsageRule {
    pub fn new() -> Self {
        Self {
            id: RuleId::new("owasp:eval-usage").expect("valid rule id"),
        }
    }
}

impl Default for EvalUsageRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for EvalUsageRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn applies_to(&self, language: &LanguageIdentifier) -> bool {
        *language == LanguageIdentifier::typescript() || *language == LanguageIdentifier::python()
    }

    fn default_severity(&self) -> Severity {
        Severity::Critical
    }

    fn issue_type(&self) -> IssueType {
        IssueType::Vulnerability
    }

    fn metadata(&self) -> vord_rules_engine::RuleMetadata {
        vord_rules_engine::RuleMetadata {
            description: "Dynamic code execution (eval / new Function / exec) runs arbitrary code and must be avoided.".into(),
            tags: vec!["security".into(), "owasp-a03".into()],
            cwe: Some(95),
            produces_hotspots: false,
        }
    }

    fn check(&self, file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        let python = *file.language() == LanguageIdentifier::python();
        ast.descendants()
            .filter(|n| *n.kind() == NodeKind::Call)
            .filter_map(|call| {
                let callee = call.first_child()?;
                let name = match callee.kind() {
                    NodeKind::Identifier => callee.text(),
                    _ => return None,
                };
                match name {
                    "eval" => Some(Finding::new(
                        "use of `eval` executes arbitrary code",
                        call.span(),
                    )),
                    "Function" if !python => Some(Finding::new(
                        "`new Function(...)` executes arbitrary code",
                        call.span(),
                    )),
                    "exec" if python => Some(Finding::new(
                        "use of `exec` executes arbitrary code",
                        call.span(),
                    )),
                    _ => None,
                }
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
        EvalUsageRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_eval_and_new_function() {
        let findings = check("eval(payload);\nconst f = new Function(body);\n");
        assert_eq!(findings.len(), 2);
    }

    #[test]
    fn ignores_regular_calls() {
        assert!(check("evaluate(x);\nconsole.log(y);\n").is_empty());
    }
}
