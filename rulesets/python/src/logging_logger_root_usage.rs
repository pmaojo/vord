//! Rule: flags a log call made directly on the `logging` module
//! (`logging.info(...)`, `logging.error(...)`, ...) instead of a module
//! or class scoped logger obtained via `logging.getLogger(__name__)`.
//! The root logger is a single shared instance: every caller of it gets
//! the same handlers and level, so there is no way to configure one
//! module's verbosity without affecting every other module in the process.

use vord_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use vord_rules_engine::{Finding, Rule, RuleId, Severity};

const LOG_METHODS: &[&str] = &[
    "debug",
    "info",
    "warning",
    "warn",
    "error",
    "critical",
    "exception",
    "log",
];

pub struct LoggingLoggerRootUsageRule {
    id: RuleId,
}

impl LoggingLoggerRootUsageRule {
    pub fn new() -> Self {
        Self {
            id: RuleId::new("python:logging-logger-root-usage").expect("valid rule id"),
        }
    }
}

impl Default for LoggingLoggerRootUsageRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for LoggingLoggerRootUsageRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn applies_to(&self, lang: &LanguageIdentifier) -> bool {
        *lang == LanguageIdentifier::python()
    }

    fn default_severity(&self) -> Severity {
        Severity::Minor
    }

    fn remediation_effort_minutes(&self) -> u32 {
        10
    }

    fn metadata(&self) -> vord_rules_engine::RuleMetadata {
        vord_rules_engine::RuleMetadata {
            description: "Logging directly through the `logging` module calls the shared root logger, so every module ends up with the same handlers and level; use logging.getLogger(__name__) and log through that instance instead.".into(),
            tags: vec!["maintainability".into(), "observability".into()],
            cwe: None,
            produces_hotspots: false,
        }
    }

    fn check(&self, _file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        ast.descendants()
            .filter(|n| *n.kind() == NodeKind::Call)
            .filter_map(|call| {
                let callee = call.first_child()?;
                if callee.kind() != &NodeKind::MemberAccess {
                    return None;
                }
                let object = callee.children().first()?;
                let method = callee.children().last()?;
                if object.text() != "logging" || !LOG_METHODS.contains(&method.text()) {
                    return None;
                }
                Some(Finding::new(
                    "logging call goes straight to the shared root logger; use logging.getLogger(__name__) so this module's verbosity can be configured independently",
                    call.span(),
                ))
            })
            .collect()
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
        LoggingLoggerRootUsageRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_root_logger_info() {
        assert_eq!(findings("logging.info('starting up')\n").len(), 1);
    }

    #[test]
    fn flags_root_logger_error() {
        assert_eq!(findings("logging.error('boom')\n").len(), 1);
    }

    #[test]
    fn allows_module_logger() {
        assert!(findings("logger = logging.getLogger(__name__)\nlogger.info('starting up')\n").is_empty());
    }

    #[test]
    fn ignores_unrelated_calls() {
        assert!(findings("logging.getLogger(__name__)\n").is_empty());
    }
}
