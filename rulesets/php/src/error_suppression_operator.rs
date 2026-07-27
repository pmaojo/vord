use yunq_ast::{AstNode, LanguageIdentifier, SourceFile};
use yunq_rules_engine::{Finding, IssueType, Rule, RuleId, Severity};

use crate::common::is_other;

/// The `@` error-control operator silently discards whatever
/// warning/notice/error the expression it prefixes would have raised —
/// including ones that would have pointed straight at a real bug (a
/// missing file, an unset array key, a failed connection). It also
/// silently overrides the project's real error-reporting configuration for
/// that one line, so a monitored, logged failure elsewhere in the app
/// becomes invisible here. Handle the specific failure instead (an `if
/// (...)` check, a `try`/`catch`, `isset()`/`??`).
pub struct ErrorSuppressionOperatorRule {
    id: RuleId,
}

impl ErrorSuppressionOperatorRule {
    pub fn new() -> Self {
        Self { id: RuleId::new("php:error-suppression-operator").expect("valid rule id") }
    }
}

impl Default for ErrorSuppressionOperatorRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for ErrorSuppressionOperatorRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn applies_to(&self, language: &LanguageIdentifier) -> bool {
        *language == LanguageIdentifier::php()
    }

    fn default_severity(&self) -> Severity {
        Severity::Minor
    }

    fn issue_type(&self) -> IssueType {
        IssueType::CodeSmell
    }

    fn metadata(&self) -> yunq_rules_engine::RuleMetadata {
        yunq_rules_engine::RuleMetadata {
            description: "The `@` error-control operator silently discards whatever \
                warning/notice/error the expression would have raised, hiding real failures \
                instead of handling them. Handle the specific failure mode instead (a check, \
                `try`/`catch`, `isset()`/`??`)."
                .into(),
            tags: vec!["reliability".into(), "php".into()],
            cwe: Some(390),
            produces_hotspots: false,
        }
    }

    fn check(&self, _file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        ast.descendants()
            .filter(|n| is_other(n.kind(), "error_suppression_expression"))
            .map(|n| {
                Finding::new(
                    "`@` silently discards this expression's warnings/errors instead of \
                    handling the failure"
                        .to_string(),
                    n.span(),
                )
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use yunq_ast::SourceFile;
    use yunq_rules_engine::AstParser;

    use super::*;

    fn check(code: &str) -> Vec<Finding> {
        let file = SourceFile::new("t.php", code, LanguageIdentifier::php()).unwrap();
        let ast = yunq_parser_php::PhpParser::new().parse(&file).unwrap();
        ErrorSuppressionOperatorRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_error_suppression_on_call() {
        assert_eq!(check("<?php\n@file_get_contents($url);\n").len(), 1);
    }

    #[test]
    fn ignores_code_without_suppression() {
        assert!(check("<?php\nfile_get_contents($url);\n").is_empty());
    }
}
