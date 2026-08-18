//! Rule: flags a `@app.task`/`@shared_task` decorated function that
//! doesn't set `time_limit`/`soft_time_limit`. Without one, a task that
//! hangs (a stuck network call, an infinite loop, a deadlock) occupies its
//! worker slot forever instead of being killed and retried, quietly
//! draining the pool's capacity.

use vord_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use vord_rules_engine::{Finding, IssueType, Rule, RuleId, Severity};

use crate::common::other_kind_name;

fn is_task_decorator_callee(callee: &AstNode) -> bool {
    let text = callee.text();
    text == "shared_task" || text.ends_with(".task")
}

fn has_time_limit_argument(call: &AstNode) -> bool {
    let Some(args) = call
        .children()
        .iter()
        .find(|c| other_kind_name(c) == Some("argument_list"))
    else {
        return false;
    };
    args.children().iter().any(|arg| {
        other_kind_name(arg) == Some("keyword_argument")
            && arg.children().first().is_some_and(|name| {
                name.text() == "time_limit" || name.text() == "soft_time_limit"
            })
    })
}

/// `None` when this decorator isn't a Celery task decorator at all. `Some(true)`
/// when it is one and already sets a time limit; `Some(false)` when it's one
/// and doesn't.
fn task_decorator_has_time_limit(decorator: &AstNode) -> Option<bool> {
    let inner = decorator.children().first()?;
    if inner.kind() == &NodeKind::Call {
        let callee = inner.first_child()?;
        is_task_decorator_callee(callee).then(|| has_time_limit_argument(inner))
    } else {
        is_task_decorator_callee(inner).then_some(false)
    }
}

pub struct CeleryTaskMissingTimeoutRule {
    id: RuleId,
}

impl CeleryTaskMissingTimeoutRule {
    pub fn new() -> Self {
        Self {
            id: RuleId::new("python:celery-task-missing-timeout").expect("valid rule id"),
        }
    }
}

impl Default for CeleryTaskMissingTimeoutRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for CeleryTaskMissingTimeoutRule {
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
        IssueType::Bug
    }

    fn remediation_effort_minutes(&self) -> u32 {
        10
    }

    fn metadata(&self) -> vord_rules_engine::RuleMetadata {
        vord_rules_engine::RuleMetadata {
            description: "A Celery task with no time_limit/soft_time_limit occupies its worker slot forever if it hangs instead of being killed and retried; set one on the task decorator.".into(),
            tags: vec!["reliability".into(), "cwe".into()],
            cwe: Some(400),
            produces_hotspots: false,
        }
    }

    fn check(&self, file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        if crate::common::is_test_file(file.path()) {
            return Vec::new();
        }
        ast.descendants()
            .filter(|n| other_kind_name(n) == Some("decorated_definition"))
            .flat_map(|n| n.children().iter().find(|c| other_kind_name(c) == Some("decorator")))
            .filter_map(|decorator| {
                (task_decorator_has_time_limit(decorator) == Some(false)).then(|| {
                    Finding::new(
                        "Celery task has no time_limit/soft_time_limit; a hung task occupies its worker slot forever instead of being killed and retried",
                        decorator.span(),
                    )
                })
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
        CeleryTaskMissingTimeoutRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_bare_shared_task() {
        assert_eq!(findings("@shared_task\ndef f():\n    pass\n").len(), 1);
    }

    #[test]
    fn flags_app_task_without_time_limit() {
        assert_eq!(findings("@app.task\ndef f():\n    pass\n").len(), 1);
    }

    #[test]
    fn flags_app_task_call_without_time_limit() {
        assert_eq!(findings("@app.task(bind=True)\ndef f():\n    pass\n").len(), 1);
    }

    #[test]
    fn allows_task_with_time_limit() {
        assert!(findings("@app.task(time_limit=30)\ndef f():\n    pass\n").is_empty());
    }

    #[test]
    fn allows_task_with_soft_time_limit() {
        assert!(findings("@app.task(soft_time_limit=30)\ndef f():\n    pass\n").is_empty());
    }

    #[test]
    fn ignores_unrelated_decorator() {
        assert!(findings("@app.route('/x')\ndef f():\n    pass\n").is_empty());
    }
}
