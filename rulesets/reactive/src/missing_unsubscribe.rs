//! Rule: an Observable subscription (`.subscribe(...)`) stored in a
//! variable or field with no matching `.unsubscribe()` call anywhere in the
//! file — a classic RxJS resource leak: the subscription (and everything it
//! holds a reference to via its callback closures) outlives whatever
//! created it. `takeUntil(...)` in the operator chain is a recognized
//! self-managed-teardown idiom and is exempted, since the subscription ends
//! itself without an explicit `.unsubscribe()` call ever appearing.

use yunq_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use yunq_rules_engine::{Finding, IssueType, Rule, RuleId, RuleMetadata, Severity};

use crate::common::{bindable_target, has_call_on_receiver, rhs_method_call};

pub struct MissingUnsubscribeRule {
    id: RuleId,
}

impl MissingUnsubscribeRule {
    pub fn new() -> Self {
        Self {
            id: RuleId::new("reactive:missing-unsubscribe").expect("valid rule id"),
        }
    }
}

impl Default for MissingUnsubscribeRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for MissingUnsubscribeRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn applies_to(&self, lang: &LanguageIdentifier) -> bool {
        *lang == LanguageIdentifier::typescript()
    }

    fn default_severity(&self) -> Severity {
        Severity::Major
    }

    fn issue_type(&self) -> IssueType {
        IssueType::Bug
    }

    fn metadata(&self) -> RuleMetadata {
        RuleMetadata {
            description: "An Observable subscription is stored but never unsubscribed, leaking the subscription and whatever its callbacks reference.".into(),
            tags: vec!["rxjs".into(), "reactive".into(), "memory-leak".into()],
            cwe: Some(401),
            produces_hotspots: false,
        }
    }

    fn check(&self, _file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        ast.descendants()
            .filter(|n| matches!(n.kind(), NodeKind::Assignment | NodeKind::VariableDecl))
            .filter_map(|decl| {
                let target = bindable_target(decl)?;
                let subscribe_call = rhs_method_call(decl, "subscribe")?;
                if subscribe_call.subtree_contains_text("takeUntil(") {
                    return None;
                }
                if has_call_on_receiver(ast, target.text(), "unsubscribe") {
                    return None;
                }
                Some(Finding::new(
                    format!(
                        "`{}` is subscribed but never `.unsubscribe()`d — the subscription (and everything its callbacks reference) leaks",
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
    use yunq_rules_engine::AstParser;

    fn check(code: &str) -> Vec<Finding> {
        let file = SourceFile::new("t.ts", code, LanguageIdentifier::typescript()).unwrap();
        let ast = yunq_parser_typescript::TypeScriptParser::new()
            .parse(&file)
            .unwrap();
        MissingUnsubscribeRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_field_subscription_never_unsubscribed() {
        let findings = check(
            "class C {\n  ngOnInit() {\n    this.sub = source$.subscribe((x) => console.log(x));\n  }\n}\n",
        );
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("this.sub"));
    }

    #[test]
    fn allows_subscription_cleaned_up_in_ondestroy() {
        let findings = check(
            "class C {\n  ngOnInit() {\n    this.sub = source$.subscribe((x) => console.log(x));\n  }\n  ngOnDestroy() {\n    this.sub.unsubscribe();\n  }\n}\n",
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn allows_local_subscription_unsubscribed_in_the_same_function() {
        let findings = check(
            "function run() {\n  const sub = source$.subscribe((x) => console.log(x));\n  sub.unsubscribe();\n}\n",
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn allows_take_until_managed_subscription() {
        let findings = check(
            "class C {\n  ngOnInit() {\n    this.sub = source$.pipe(takeUntil(this.destroy$)).subscribe((x) => console.log(x));\n  }\n}\n",
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn flags_local_subscription_never_unsubscribed() {
        let findings =
            check("function run() {\n  const sub = source$.subscribe((x) => console.log(x));\n}\n");
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn ignores_declarations_with_no_subscribe_call() {
        let findings = check("function run() {\n  const x = source$.pipe(map((v) => v));\n}\n");
        assert!(findings.is_empty());
    }
}
