//! Rule: a `Subject`/`BehaviorSubject`/`ReplaySubject`/`AsyncSubject`
//! created but never `.complete()`d — anything downstream relying on stream
//! completion (`takeUntil`, `finalize`, an async `for await` loop) never
//! fires, and the subject (plus every subscriber still attached to it)
//! outlives its useful lifetime.

use vord_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use vord_rules_engine::{Finding, IssueType, Rule, RuleId, RuleMetadata, Severity};

use crate::common::{bindable_target, has_call_on_receiver};

const SUBJECT_TYPES: &[&str] = &[
    "Subject",
    "BehaviorSubject",
    "ReplaySubject",
    "AsyncSubject",
];

/// The constructed type's simple name if `expr` is `new <Type>(...)` —
/// tolerates a generic type argument (`new Subject<void>()`): the
/// constructor name is still the `Call`'s first named child regardless of
/// the type-argument node tree-sitter inserts between it and the argument
/// list.
fn new_expression_type(expr: &AstNode) -> Option<&str> {
    if *expr.kind() != NodeKind::Call || !expr.text().trim_start().starts_with("new ") {
        return None;
    }
    expr.first_child()
        .filter(|c| *c.kind() == NodeKind::Identifier)
        .map(|c| c.text())
}

pub struct SubjectNeverCompletedRule {
    id: RuleId,
}

impl SubjectNeverCompletedRule {
    pub fn new() -> Self {
        Self {
            id: RuleId::new("reactive:subject-never-completed").expect("valid rule id"),
        }
    }
}

impl Default for SubjectNeverCompletedRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for SubjectNeverCompletedRule {
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

    fn metadata(&self) -> RuleMetadata {
        RuleMetadata {
            description: "A Subject is created but never completed, so anything relying on stream completion downstream (takeUntil, finalize, ...) never fires.".into(),
            tags: vec!["rxjs".into(), "reactive".into()],
            cwe: None,
            produces_hotspots: false,
        }
    }

    fn check(&self, _file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        ast.descendants()
            .filter(|n| matches!(n.kind(), NodeKind::Assignment | NodeKind::VariableDecl))
            .filter_map(|decl| {
                let target = bindable_target(decl)?;
                let subject_type = decl
                    .children()
                    .iter()
                    .skip(1)
                    .find_map(|value| new_expression_type(value))?;
                if !SUBJECT_TYPES.contains(&subject_type) {
                    return None;
                }
                if has_call_on_receiver(ast, target.text(), "complete") {
                    return None;
                }
                Some(Finding::new(
                    format!(
                        "`{}` ({subject_type}) is created but never `.complete()`d",
                        target.text()
                    ),
                    decl.span(),
                ))
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vord_rules_engine::AstParser;

    fn check(code: &str) -> Vec<Finding> {
        let file = SourceFile::new("t.ts", code, LanguageIdentifier::typescript()).unwrap();
        let ast = vord_parser_typescript::TypeScriptParser::new()
            .parse(&file)
            .unwrap();
        SubjectNeverCompletedRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_subject_never_completed() {
        let findings =
            check("class C {\n  ngOnInit() {\n    this.destroy$ = new Subject();\n  }\n}\n");
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("this.destroy$"));
    }

    #[test]
    fn allows_subject_completed_in_ondestroy() {
        let findings = check(
            "class C {\n  ngOnInit() {\n    this.destroy$ = new Subject();\n  }\n  ngOnDestroy() {\n    this.destroy$.complete();\n  }\n}\n",
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn flags_behavior_subject_with_generic_type_argument() {
        let findings =
            check("function run() {\n  const state$ = new BehaviorSubject<number>(0);\n}\n");
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("BehaviorSubject"));
    }

    #[test]
    fn ignores_non_subject_constructors() {
        let findings = check("function run() {\n  const x = new Map();\n}\n");
        assert!(findings.is_empty());
    }
}
