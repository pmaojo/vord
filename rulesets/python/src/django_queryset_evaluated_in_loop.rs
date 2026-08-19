//! Rule: flags a Django ORM queryset call (`.objects.filter(...)`,
//! `.objects.get(...)`, `.objects.all()`, ...) made inside a `for` loop
//! body. Each iteration issues its own database round trip — the classic
//! N+1 query problem — instead of fetching everything once before the
//! loop with `select_related`/`prefetch_related` or a single bulk query.

use vord_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use vord_rules_engine::{Finding, IssueType, Rule, RuleId, Severity};

use crate::common::other_kind_name;

fn is_queryset_call(call: &AstNode) -> bool {
    call.first_child().is_some_and(|callee| {
        callee.kind() == &NodeKind::MemberAccess && callee.text().contains(".objects.")
    })
}

pub struct DjangoQuerysetEvaluatedInLoopRule {
    id: RuleId,
}

impl DjangoQuerysetEvaluatedInLoopRule {
    pub fn new() -> Self {
        Self {
            id: RuleId::new("python:django-queryset-evaluated-in-loop").expect("valid rule id"),
        }
    }
}

impl Default for DjangoQuerysetEvaluatedInLoopRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for DjangoQuerysetEvaluatedInLoopRule {
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
        IssueType::CodeSmell
    }

    fn remediation_effort_minutes(&self) -> u32 {
        20
    }

    fn metadata(&self) -> vord_rules_engine::RuleMetadata {
        vord_rules_engine::RuleMetadata {
            description: "A Django ORM queryset call made inside a for loop issues one database round trip per iteration (the N+1 query problem); fetch everything once before the loop with select_related/prefetch_related or a single bulk query.".into(),
            tags: vec!["performance".into(), "database".into()],
            cwe: None,
            produces_hotspots: false,
        }
    }

    fn check(&self, file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        if crate::common::is_test_file(file.path()) {
            return Vec::new();
        }
        ast.descendants()
            .filter(|n| other_kind_name(n) == Some("for_statement"))
            .filter_map(|for_stmt| for_stmt.children().iter().find(|c| other_kind_name(c) == Some("block")))
            .flat_map(|block| block.descendants())
            .filter(|n| *n.kind() == NodeKind::Call)
            .filter(|call| is_queryset_call(call))
            .map(|call| Finding::new("Django queryset call inside a for loop issues one database round trip per iteration; fetch this once before the loop instead", call.span()))
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
        DjangoQuerysetEvaluatedInLoopRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_filter_call_inside_for_loop() {
        let code = "for order in orders:\n    items = Item.objects.filter(order=order)\n";
        assert_eq!(findings(code).len(), 1);
    }

    #[test]
    fn flags_get_call_inside_for_loop() {
        let code = "for pk in ids:\n    obj = Model.objects.get(pk=pk)\n";
        assert_eq!(findings(code).len(), 1);
    }

    #[test]
    fn allows_queryset_call_before_loop() {
        let code = "items = Item.objects.filter(active=True)\nfor item in items:\n    process(item)\n";
        assert!(findings(code).is_empty());
    }

    #[test]
    fn ignores_unrelated_calls_in_loop() {
        let code = "for item in items:\n    process(item)\n";
        assert!(findings(code).is_empty());
    }
}
