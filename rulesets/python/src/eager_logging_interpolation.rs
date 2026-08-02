//! Rule: flags a logging call whose message is built eagerly (an
//! f-string, `%`-formatting, or `+` concatenation applied before the
//! call) instead of passed as a format string plus separate arguments.
//! The eager form always pays the formatting cost, even when the log
//! level is disabled and the message is never emitted.

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
];

fn other_kind_name(node: &AstNode) -> Option<&str> {
    match node.kind() {
        NodeKind::Other(name) => Some(name.as_ref()),
        _ => None,
    }
}

fn looks_like_logger(object_text: &str) -> bool {
    let lower = object_text.to_ascii_lowercase();
    lower == "log" || lower == "logging" || lower.ends_with("logger") || lower.ends_with("_log")
}

fn is_eager_message(arg: &AstNode) -> bool {
    match arg.kind() {
        NodeKind::StringLiteral => arg.first_child().is_some_and(|start| {
            other_kind_name(start) == Some("string_start")
                && start.text().trim_start().starts_with(['f', 'F'])
        }),
        NodeKind::Other(name) => name.as_ref() == "binary_operator",
        _ => false,
    }
}

pub struct EagerLoggingInterpolationRule {
    id: RuleId,
}

impl EagerLoggingInterpolationRule {
    pub fn new() -> Self {
        Self {
            id: RuleId::new("python:eager-logging-interpolation").expect("valid rule id"),
        }
    }
}

impl Default for EagerLoggingInterpolationRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for EagerLoggingInterpolationRule {
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
        5
    }

    fn metadata(&self) -> vord_rules_engine::RuleMetadata {
        vord_rules_engine::RuleMetadata {
            description: "Building a log message eagerly (an f-string, %, or + before the call) pays the formatting cost even when the log level is disabled; pass a format string and the values as separate arguments instead.".into(),
            tags: vec!["performance".into(), "python-idiom".into()],
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
                if !looks_like_logger(object.text()) || !LOG_METHODS.contains(&method.text()) {
                    return None;
                }
                let args = call.children().iter().find(|c| other_kind_name(c) == Some("argument_list"))?;
                let first_arg = args.children().first()?;
                is_eager_message(first_arg).then(|| Finding::new("log message is built eagerly; pass a format string plus separate arguments so formatting is skipped when the level is disabled", call.span()))
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
        EagerLoggingInterpolationRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_fstring_message() {
        assert_eq!(findings("logging.info(f'x={x}')\n").len(), 1);
    }

    #[test]
    fn flags_percent_formatted_message() {
        assert_eq!(findings("logger.info('x=%s' % x)\n").len(), 1);
    }

    #[test]
    fn allows_lazy_percent_style() {
        assert!(findings("logging.info('x=%s', x)\n").is_empty());
    }

    #[test]
    fn ignores_non_logger_calls() {
        assert!(findings("printer.info(f'x={x}')\n").is_empty());
    }
}
