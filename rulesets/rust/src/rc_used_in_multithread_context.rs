use vord_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use vord_rules_engine::{Finding, IssueType, Rule, RuleId, Severity};

fn is_spawn_call(callee_text: &str) -> bool {
    callee_text.ends_with("thread::spawn")
        || callee_text.ends_with("tokio::spawn")
        || callee_text.ends_with("task::spawn")
        || callee_text.ends_with("rayon::spawn")
}

/// Whether the argument list handed to a `spawn`-style call textually
/// mentions `Rc`, either constructing one (`Rc::new(`) or naming the type
/// (`Rc<`). `Rc` is neither `Send` nor `Sync`, so moving or capturing one
/// into a spawned task's closure is unsound and — for `thread::spawn` and
/// `tokio::spawn` specifically — a hard compile error; catching it here
/// gives a faster, more legible signal than the trait-bound error the
/// compiler eventually produces.
fn arguments_mention_rc(call: &AstNode) -> bool {
    let text = call.text();
    let Some(open_paren) = text.find('(') else {
        return false;
    };
    let args = &text[open_paren..];
    args.contains("Rc::new(") || args.contains("Rc<")
}

pub struct RcUsedInMultithreadContextRule {
    id: RuleId,
}

impl RcUsedInMultithreadContextRule {
    pub fn new() -> Self {
        Self {
            id: RuleId::new("rust:rc-used-in-multithread-context").expect("valid rule id"),
        }
    }
}

impl Default for RcUsedInMultithreadContextRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for RcUsedInMultithreadContextRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn applies_to(&self, language: &LanguageIdentifier) -> bool {
        *language == LanguageIdentifier::rust()
    }

    fn default_severity(&self) -> Severity {
        Severity::Major
    }

    fn issue_type(&self) -> IssueType {
        IssueType::Bug
    }

    fn remediation_effort_minutes(&self) -> u32 {
        10
    }

    fn metadata(&self) -> vord_rules_engine::RuleMetadata {
        vord_rules_engine::RuleMetadata {
            description: "`Rc<T>` is not `Send`/`Sync`; constructing or naming one inside a \
                `thread::spawn`/`tokio::spawn` task body means the task can't cross threads \
                soundly. Use `Arc<T>` (with a `Mutex`/`RwLock` if interior mutability is \
                needed) for values shared across threads."
                .into(),
            tags: vec!["concurrency".into(), "rust".into()],
            cwe: None,
            produces_hotspots: false,
        }
    }

    fn check(&self, file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        let test_ranges = vord_rules_engine::rust_test_module_ranges(file.content());

        ast.descendants()
            .filter(|n| *n.kind() == NodeKind::Call)
            .filter(|call| call.first_child().is_some_and(|c| is_spawn_call(c.text())))
            .filter(|call| arguments_mention_rc(call))
            .filter(|call| !vord_rules_engine::in_ranges(&test_ranges, call.span().start_line))
            .map(|call| {
                Finding::new(
                    "this spawned task's body mentions `Rc`, which is not `Send`/`Sync`; use \
                    `Arc` for values shared across threads"
                        .to_string(),
                    call.span(),
                )
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
        let file = SourceFile::new("t.rs", code, LanguageIdentifier::rust()).unwrap();
        let ast = vord_parser_rust::RustParser::new().parse(&file).unwrap();
        RcUsedInMultithreadContextRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_rc_new_inside_thread_spawn() {
        let findings =
            check("fn f() { std::thread::spawn(move || { let v = Rc::new(5); use_it(v); }); }\n");
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn flags_rc_type_inside_tokio_spawn() {
        let findings = check(
            "fn f(v: Rc<Data>) { tokio::spawn(async move { let x: Rc<Data> = v; use_it(x); }); }\n",
        );
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn ignores_arc_inside_thread_spawn() {
        assert!(
            check(
                "fn f(v: std::sync::Arc<Data>) { std::thread::spawn(move || { use_it(v); }); }\n"
            )
            .is_empty()
        );
    }

    #[test]
    fn ignores_rc_outside_a_spawn_call() {
        assert!(check("fn f() { let v = Rc::new(5); use_it(v); }\n").is_empty());
    }

    #[test]
    fn ignores_rc_used_in_multithread_context_inside_a_cfg_test_module() {
        let code = "fn prod() {}\n\n#[cfg(test)]\nmod tests {\n    #[test]\n    fn t() {\n        std::thread::spawn(move || { let v = Rc::new(5); use_it(v); });\n    }\n}\n";
        assert!(check(code).is_empty());
    }
}
