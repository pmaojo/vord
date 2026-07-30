//! Rule: a Gherkin step's implementation calls infrastructure directly instead
//! of going through the application layer. A BDD scenario is supposed to
//! specify *behavior* — `When the customer places an order` reads as a
//! business action regardless of what backs it — and the step-definition
//! function that binds it is supposed to be a thin adapter that turns that
//! business language into a call on a use case or port. A step body that
//! calls `axios.get(...)` or `reqwest::get(...)` itself has skipped the
//! application layer entirely: the scenario now specifies an HTTP call, not a
//! business behavior, and every other scenario that should exercise the same
//! use case has to reinvent — or diverge from — however this one talks to the
//! server.
//!
//! Two independent recognizers, deliberately narrow:
//! - **Is this a step definition at all**, per the binding convention each
//!   ecosystem actually uses: Cucumber-js's `Given('...', fn)`/`When`/`Then`
//!   calls (TypeScript), `behave`'s `@given(...)`/`@when`/`@then` decorators
//!   (Python), `cucumber-rs`'s `#[given(...)]`/`#[when]`/`#[then]` attributes
//!   (Rust). Go is deliberately not covered: unlike the other three, it has no
//!   single dominant Gherkin-binding convention (`godog` exists, but much of
//!   the ecosystem's "BDD" is Ginkgo/Gomega, which is not Gherkin at all), so
//!   a fourth recognizer here would be guessing rather than reading a
//!   convention.
//! - **Does it reach infrastructure**, reusing
//!   `yunq_import_graph::infra_roster` — the identical curated module list
//!   `architecture:framework-in-domain` checks against a file's imports,
//!   applied instead to call sites inside the step body: a call whose callee
//!   resolves to a bare identifier matching one of the roster's single-word
//!   module names (`axios`, `requests`, `reqwest`, `sqlx`, …). Scoped names
//!   (`node:fs`, `@nestjs/common`, `std::fs`) are excluded from the candidate
//!   set on purpose — they are never how code actually spells a call
//!   (`fs.readFile(..)`, not `node:fs.readFile(..)`), so keeping them in would
//!   only ever miss, never over-match.

use yunq_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use yunq_import_graph::{infra_roster, InfraModule};
use yunq_rules_engine::{Finding, IssueType, Rule, RuleId, RuleMetadata, Severity};

fn is_other(node: &AstNode, kind: &str) -> bool {
    matches!(node.kind(), NodeKind::Other(k) if k.as_ref() == kind)
}

/// A `Call` node's own arguments, unwrapped from the `arguments` node every
/// grammar here wraps them in — `Call`'s own children are just `[callee,
/// arguments-wrapper]`, not `[callee, arg1, arg2, ..]`.
fn call_arguments(call: &AstNode) -> &[AstNode] {
    call.children().get(1).map(|args| args.children()).unwrap_or(&[])
}

/// Every step-definition function `Given`/`When`/`Then(...)` binds in a
/// Cucumber-js file: the last function-valued argument of the call.
fn ts_step_bodies(ast: &AstNode) -> Vec<&AstNode> {
    ast.descendants()
        .filter(|node| *node.kind() == NodeKind::Call)
        .filter_map(|call| {
            let callee = call.first_child()?;
            if *callee.kind() != NodeKind::Identifier || !["Given", "When", "Then"].contains(&callee.text()) {
                return None;
            }
            call_arguments(call).iter().rev().find(|child| *child.kind() == NodeKind::FunctionDef)
        })
        .collect()
}

/// Every step-definition function a `behave` `@given`/`@when`/`@then`
/// decorator wraps.
fn python_step_bodies(ast: &AstNode) -> Vec<&AstNode> {
    ast.descendants()
        .filter(|node| is_other(node, "decorated_definition"))
        .filter_map(|decorated| {
            let is_step = decorated.children().iter().any(|child| {
                is_other(child, "decorator")
                    && ["@given", "@when", "@then"]
                        .iter()
                        .any(|marker| child.text().to_ascii_lowercase().starts_with(marker))
            });
            is_step.then(|| decorated.children().iter().find(|c| *c.kind() == NodeKind::FunctionDef)).flatten()
        })
        .collect()
}

/// Every step-definition function a `cucumber-rs`
/// `#[given]`/`#[when]`/`#[then]` attribute precedes — the same "the
/// attribute applies to the next non-attribute item" shape
/// `ddd::common::wire_dto_names` already reads off a stacked `#[derive]`.
fn rust_step_bodies(ast: &AstNode) -> Vec<&AstNode> {
    let mut bodies = Vec::new();
    for parent in ast.descendants() {
        let children = parent.children();
        for (index, node) in children.iter().enumerate() {
            if !is_other(node, "attribute_item") {
                continue;
            }
            let lower = node.text().to_ascii_lowercase();
            if !["#[given", "#[when", "#[then"].iter().any(|marker| lower.starts_with(marker)) {
                continue;
            }
            let function = children[index + 1..]
                .iter()
                .find(|next| !is_other(next, "attribute_item"))
                .filter(|next| *next.kind() == NodeKind::FunctionDef);
            if let Some(function) = function {
                bodies.push(function);
            }
        }
    }
    bodies
}

fn step_bodies<'a>(ast: &'a AstNode, language: &LanguageIdentifier) -> Vec<&'a AstNode> {
    if *language == LanguageIdentifier::typescript() {
        return ts_step_bodies(ast);
    }
    if *language == LanguageIdentifier::python() {
        return python_step_bodies(ast);
    }
    if *language == LanguageIdentifier::rust() {
        return rust_step_bodies(ast);
    }
    Vec::new()
}

/// The identifier a (possibly chained) member-access expression is ultimately
/// read off of: `a.b.c` (TS/Python's `MemberAccess`) and Rust's `a::b::c`
/// (a `scoped_identifier`, which shares the same `[base, ..]` shape but keeps
/// its own grammar kind rather than mapping onto `MemberAccess`) both resolve
/// to `a`.
fn root_identifier(expression: &AstNode) -> Option<&str> {
    let mut node = expression;
    loop {
        match node.kind() {
            NodeKind::Identifier => return Some(node.text()),
            NodeKind::MemberAccess => node = node.first_child()?,
            NodeKind::Other(kind) if kind.as_ref() == "scoped_identifier" => node = node.first_child()?,
            _ => return None,
        }
    }
}

/// The roster entries whose module name is a single bare word — the only
/// ones a call site could ever spell as a plain identifier
/// (`axios.get(..)`), as opposed to a scoped or path-shaped specifier
/// (`node:fs`, `@nestjs/common`, `std::fs`) that never appears in source as
/// its own identifier.
fn bare_word_modules(language: &LanguageIdentifier) -> Vec<&'static InfraModule> {
    infra_roster(language).iter().filter(|entry| !entry.module.contains(['/', '.', ':', '@'])).collect()
}

/// The first infra-roster module `body` calls into, if any.
fn infra_call_in(body: &AstNode, language: &LanguageIdentifier) -> Option<&'static InfraModule> {
    let candidates = bare_word_modules(language);
    body.descendants().filter(|node| *node.kind() == NodeKind::Call).find_map(|call| {
        let callee = call.first_child()?;
        let root = root_identifier(callee)?;
        candidates.iter().find(|entry| entry.module == root).copied()
    })
}

pub struct BddStepReachesInfraRule {
    id: RuleId,
}

impl BddStepReachesInfraRule {
    pub fn new() -> Self {
        Self { id: RuleId::new("ddd:bdd-step-reaches-infra").expect("valid rule id") }
    }
}

impl Default for BddStepReachesInfraRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for BddStepReachesInfraRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn applies_to(&self, language: &LanguageIdentifier) -> bool {
        [LanguageIdentifier::typescript(), LanguageIdentifier::python(), LanguageIdentifier::rust()]
            .contains(language)
    }

    fn default_severity(&self) -> Severity {
        Severity::Major
    }

    fn remediation_effort_minutes(&self) -> u32 {
        30
    }

    fn issue_type(&self) -> IssueType {
        IssueType::CodeSmell
    }

    fn metadata(&self) -> RuleMetadata {
        RuleMetadata {
            description: "A Gherkin step's implementation calls infrastructure (an HTTP client, a database driver, an ORM) directly instead of going through the application layer's use case or port. Route the step through the use case the scenario is meant to specify, and leave the technical call to whatever adapter that use case already depends on.".into(),
            tags: vec!["ddd".into(), "bdd".into(), "hexagonal".into()],
            cwe: None,
            produces_hotspots: false,
        }
    }

    fn check(&self, file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        let language = file.language();
        step_bodies(ast, language)
            .into_iter()
            .filter_map(|body| {
                let hit = infra_call_in(body, language)?;
                Some(Finding::new(
                    format!(
                        "this Gherkin step implementation calls `{}` ({}) directly — route it through the application's use case or port instead of talking to infrastructure from the step definition",
                        hit.module, hit.concern
                    ),
                    body.span(),
                ))
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use yunq_rules_engine::AstParser;

    fn check(path: &str, code: &str, language: LanguageIdentifier) -> Vec<Finding> {
        let file = SourceFile::new(path, code, language.clone()).unwrap();
        let ast = if language == LanguageIdentifier::typescript() {
            yunq_parser_typescript::TypeScriptParser::new().parse(&file).unwrap()
        } else if language == LanguageIdentifier::python() {
            yunq_parser_python::PythonParser::new().parse(&file).unwrap()
        } else {
            yunq_parser_rust::RustParser::new().parse(&file).unwrap()
        };
        BddStepReachesInfraRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_a_cucumber_js_step_that_calls_axios_directly() {
        let code = "Given('an order exists', function () {\n  axios.get('/orders/1');\n});\n";
        let findings = check("features/step_definitions/order_steps.ts", code, LanguageIdentifier::typescript());
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert!(findings[0].message.contains("`axios`"), "{}", findings[0].message);
        assert!(findings[0].message.contains("an HTTP client"));
    }

    #[test]
    fn flags_a_cucumber_js_arrow_function_step() {
        let code = "When('the order is placed', async () => {\n  await axios.post('/orders', {});\n});\n";
        let findings = check("features/step_definitions/order_steps.ts", code, LanguageIdentifier::typescript());
        assert_eq!(findings.len(), 1, "{findings:?}");
    }

    #[test]
    fn silent_when_the_step_calls_a_use_case_instead() {
        let code = "When('the order is placed', function () {\n  placeOrder.execute(this.command);\n});\n";
        assert!(check("features/step_definitions/order_steps.ts", code, LanguageIdentifier::typescript())
            .is_empty());
    }

    #[test]
    fn silent_on_an_ordinary_test_that_is_not_a_step_definition() {
        // `it(...)` is not `Given`/`When`/`Then` — an ordinary Jest test that
        // happens to call axios is not this rule's business.
        let code = "it('fetches orders', function () {\n  axios.get('/orders');\n});\n";
        assert!(check("src/order.test.ts", code, LanguageIdentifier::typescript()).is_empty());
    }

    #[test]
    fn flags_a_behave_step_that_calls_requests_directly() {
        let code = "@given('an order exists')\ndef step_impl(context):\n    requests.get('/orders/1')\n";
        let findings = check("features/steps/order_steps.py", code, LanguageIdentifier::python());
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert!(findings[0].message.contains("`requests`"));
    }

    #[test]
    fn silent_when_the_behave_step_calls_the_application_layer() {
        let code = "@when('the order is placed')\ndef step_impl(context):\n    place_order(context.command)\n";
        assert!(check("features/steps/order_steps.py", code, LanguageIdentifier::python()).is_empty());
    }

    #[test]
    fn flags_a_cucumber_rs_step_that_calls_reqwest_directly() {
        let code = "#[given(expr = \"an order exists\")]\nasync fn an_order_exists(world: &mut World) {\n    reqwest::get(\"http://localhost/orders/1\").await;\n}\n";
        let findings = check("tests/steps/order_steps.rs", code, LanguageIdentifier::rust());
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert!(findings[0].message.contains("`reqwest`"));
    }

    #[test]
    fn silent_when_the_cucumber_rs_step_calls_the_application_layer() {
        let code = "#[when(expr = \"the order is placed\")]\nasync fn the_order_is_placed(world: &mut World) {\n    place_order(&world.command).await;\n}\n";
        assert!(check("tests/steps/order_steps.rs", code, LanguageIdentifier::rust()).is_empty());
    }

    #[test]
    fn applies_only_to_typescript_python_and_rust() {
        let rule = BddStepReachesInfraRule::new();
        assert!(rule.applies_to(&LanguageIdentifier::typescript()));
        assert!(rule.applies_to(&LanguageIdentifier::python()));
        assert!(rule.applies_to(&LanguageIdentifier::rust()));
        assert!(!rule.applies_to(&LanguageIdentifier::go()));
    }
}
