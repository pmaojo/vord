//! Rule: a constructor that receives too many collaborators — constructor
//! over-injection. Dependency injection done right (see
//! `smells:concrete-dependency`, which insists on it) makes the *number* of
//! dependencies visible in one place, and a constructor asking for eight of
//! them is the Single Responsibility Principle failing out loud: a class
//! needing that many collaborators to do its job is coordinating several jobs.
//!
//! Only *collaborators* count, not parameters. A value object built from six
//! numbers is not over-injected — it is a value object — so a parameter whose
//! declared type is data (`yunq_symbols::is_primitive_type`, which sees
//! through `Vec<String>`/`Optional[int]`/`Map<string, number>`) is skipped.
//! That distinction is what separates this from a plain "too many parameters"
//! count (SonarQube's S107, CodeQL's `FunctionsWithManyParameters.ql`), which
//! both rulesets already have in the shape of `smells:long-function`'s sibling
//! metrics.
//!
//! A constructor with no type annotations at all says nothing either way, so
//! it is skipped rather than guessed at — plain untyped Python `__init__` is
//! silent here by design, not by omission.

use yunq_ast::{AstNode, LanguageIdentifier, SourceFile};
use yunq_rules_engine::{Finding, IssueType, Rule, RuleId, RuleMetadata, Severity};
use yunq_symbols::{mentions_collaborator, ClassRegistry, MethodInfo};

/// Suffixes of types that are *settings*, not services: a record of values the
/// caller assembles and hands over. A class taking four collaborators and a
/// config struct has four dependencies, not five — counting the config is how
/// this rule would punish the very refactoring ("group these knobs into one
/// type") that keeps a signature honest.
const CONFIG_SUFFIXES: &[&str] = &["Config", "Configuration", "Settings", "Options", "Params", "Args"];

fn is_config_record(declared: &str) -> bool {
    declared
        .split(|c: char| !c.is_alphanumeric() && c != '_')
        .filter(|part| !part.is_empty())
        .any(|name| CONFIG_SUFFIXES.iter().any(|suffix| name.ends_with(suffix)))
}

fn collaborator_params(constructor: &MethodInfo<'_>) -> Vec<String> {
    constructor
        .params
        .iter()
        .filter_map(|param| {
            let declared = param.declared_type.as_deref()?;
            let counts = mentions_collaborator(declared) && !is_config_record(declared);
            counts.then(|| format!("{}: {declared}", param.name))
        })
        .collect()
}

pub struct ConstructorOverInjectionRule {
    id: RuleId,
    max_collaborators: usize,
}

impl ConstructorOverInjectionRule {
    pub fn new(max_collaborators: usize) -> Self {
        Self { id: RuleId::new("smells:constructor-over-injection").expect("valid rule id"), max_collaborators }
    }
}

impl Default for ConstructorOverInjectionRule {
    /// Four collaborators is a coordinator; five is a class that should have
    /// been two. The same band Uncle Bob's "no more than a handful" advice and
    /// most DI-container linters settle on.
    fn default() -> Self {
        Self::new(4)
    }
}

impl Rule for ConstructorOverInjectionRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn applies_to(&self, language: &LanguageIdentifier) -> bool {
        [
            LanguageIdentifier::typescript(),
            LanguageIdentifier::python(),
            LanguageIdentifier::rust(),
            LanguageIdentifier::go(),
        ]
        .contains(language)
    }

    fn default_severity(&self) -> Severity {
        Severity::Major
    }

    fn remediation_effort_minutes(&self) -> u32 {
        60
    }

    fn issue_type(&self) -> IssueType {
        IssueType::CodeSmell
    }

    fn metadata(&self) -> RuleMetadata {
        RuleMetadata {
            description: "A constructor is injected with more collaborators than one responsibility needs — the class is coordinating several jobs. Data parameters are not counted; only dependencies are.".into(),
            tags: vec!["design".into(), "single-responsibility".into(), "dependency-inversion".into()],
            cwe: None,
            produces_hotspots: false,
        }
    }

    fn check(&self, file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        if yunq_rules_engine::is_test_only_path(file.path()) {
            return Vec::new();
        }
        let registry = ClassRegistry::build(ast);
        let mut findings = Vec::new();
        for class in registry.iter() {
            // `ClassInfo::constructor` knows what each language calls one —
            // `constructor`/`__init__`, Rust's `new`, Go's `New<Type>` function.
            let Some(constructor) = class.constructor() else { continue };
            if constructor.params.iter().all(|p| p.declared_type.is_none()) {
                continue; // nothing declared: no evidence either way
            }
            let collaborators = collaborator_params(constructor);
            if collaborators.len() <= self.max_collaborators {
                continue;
            }
            findings.push(Finding::new(
                format!(
                    "`{}`'s constructor takes {} injected collaborators ({}) — that many dependencies is more than one responsibility; split the class along the groups its dependencies fall into (Single Responsibility Principle)",
                    class.name,
                    collaborators.len(),
                    collaborators.join(", ")
                ),
                constructor.span,
            ));
        }
        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use yunq_rules_engine::AstParser;

    fn ts(code: &str) -> Vec<Finding> {
        let file = SourceFile::new("t.ts", code, LanguageIdentifier::typescript()).unwrap();
        let ast = yunq_parser_typescript::TypeScriptParser::new().parse(&file).unwrap();
        ConstructorOverInjectionRule::default().check(&file, &ast)
    }

    fn py(code: &str) -> Vec<Finding> {
        let file = SourceFile::new("t.py", code, LanguageIdentifier::python()).unwrap();
        let ast = yunq_parser_python::PythonParser::new().parse(&file).unwrap();
        ConstructorOverInjectionRule::default().check(&file, &ast)
    }

    fn rs(code: &str) -> Vec<Finding> {
        let file = SourceFile::new("t.rs", code, LanguageIdentifier::rust()).unwrap();
        let ast = yunq_parser_rust::RustParser::new().parse(&file).unwrap();
        ConstructorOverInjectionRule::default().check(&file, &ast)
    }

    #[test]
    fn flags_five_injected_collaborators() {
        let findings = ts(
            "class OrderService {\n  constructor(\n    orders: OrderRepository,\n    payments: PaymentGateway,\n    mail: Mailer,\n    audit: AuditLog,\n    clock: Clock,\n  ) {}\n}\n",
        );
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("5 injected collaborators"), "{}", findings[0].message);
        assert!(findings[0].message.contains("OrderService"));
    }

    #[test]
    fn allows_four_collaborators() {
        let findings = ts(
            "class OrderService {\n  constructor(\n    orders: OrderRepository,\n    payments: PaymentGateway,\n    mail: Mailer,\n    audit: AuditLog,\n  ) {}\n}\n",
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn data_parameters_are_not_collaborators() {
        let findings = ts(
            "class Money {\n  constructor(\n    amount: number,\n    currency: string,\n    scale: number,\n    rounding: string,\n    label: string,\n    note: string,\n  ) {}\n}\n",
        );
        assert!(findings.is_empty(), "a value object built from data is not over-injected: {findings:?}");
    }

    #[test]
    fn wrapped_collaborators_still_count() {
        let findings = ts(
            "class OrderService {\n  constructor(\n    orders: Array<OrderRepository>,\n    payments: PaymentGateway,\n    mail: Mailer,\n    audit: AuditLog,\n    clock: Clock,\n  ) {}\n}\n",
        );
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn flags_an_annotated_python_init() {
        let findings = py(
            "class OrderService:\n    def __init__(\n        self,\n        orders: OrderRepository,\n        payments: PaymentGateway,\n        mail: Mailer,\n        audit: AuditLog,\n        clock: Clock,\n    ):\n        pass\n",
        );
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("OrderService"));
    }

    #[test]
    fn an_unannotated_python_init_is_silent() {
        let findings = py(
            "class OrderService:\n    def __init__(self, orders, payments, mail, audit, clock):\n        pass\n",
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn flags_a_rust_new_with_five_injected_ports() {
        let findings = rs(
            "pub struct OrderService;\n\nimpl OrderService {\n    pub fn new(\n        orders: Arc<dyn OrderRepository>,\n        payments: Arc<dyn PaymentGateway>,\n        mail: Arc<dyn Mailer>,\n        audit: Arc<dyn AuditLog>,\n        clock: Arc<dyn Clock>,\n    ) -> Self {\n        Self\n    }\n}\n",
        );
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("5 injected collaborators"));
    }

    #[test]
    fn a_rust_new_taking_only_data_is_silent() {
        let findings = rs(
            "pub struct Money;\n\nimpl Money {\n    pub fn new(a: i64, b: u32, c: String, d: f64, e: bool, f: char) -> Self {\n        Self\n    }\n}\n",
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn a_configuration_record_is_not_a_collaborator() {
        let findings = ts(
            "class Runtime {\n  constructor(\n    model: Model,\n    workspace: Workspace,\n    judge: Judge,\n    analyzer: Analyzer,\n    config: RunConfig,\n  ) {}\n}\n",
        );
        assert!(findings.is_empty(), "four services and one settings record: {findings:?}");
    }

    #[test]
    fn a_conversion_bound_over_a_primitive_is_not_a_collaborator() {
        let findings = rs(
            "pub struct Issue;\n\nimpl Issue {\n    pub fn new(rule: RuleId, severity: Severity, message: impl Into<String>, file: impl Into<String>, span: Span) -> Self {\n        Self\n    }\n}\n",
        );
        assert!(findings.is_empty(), "two of these five parameters are strings: {findings:?}");
    }

    #[test]
    fn flags_a_go_constructor_function_with_five_injected_ports() {
        let file = SourceFile::new(
            "t.go",
            "package app\n\ntype OrderService struct{}\n\nfunc NewOrderService(orders OrderRepository, payments PaymentGateway, mail Mailer, audit AuditLog, clock Clock) *OrderService {\n\treturn &OrderService{}\n}\n",
            LanguageIdentifier::go(),
        )
        .unwrap();
        let ast = yunq_parser_go::GoParser::new().parse(&file).unwrap();
        let findings = ConstructorOverInjectionRule::default().check(&file, &ast);
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert!(findings[0].message.contains("5 injected collaborators"));
    }

    #[test]
    fn silent_in_test_only_paths() {
        let file = SourceFile::new(
            "tests/service.ts",
            "class S {\n  constructor(a: A, b: B, c: C, d: D, e: E) {}\n}\n",
            LanguageIdentifier::typescript(),
        )
        .unwrap();
        let ast = yunq_parser_typescript::TypeScriptParser::new().parse(&file).unwrap();
        assert!(ConstructorOverInjectionRule::default().check(&file, &ast).is_empty());
    }

    #[test]
    fn threshold_is_configurable() {
        let file = SourceFile::new(
            "t.ts",
            "class S {\n  constructor(a: A, b: B, c: C) {}\n}\n",
            LanguageIdentifier::typescript(),
        )
        .unwrap();
        let ast = yunq_parser_typescript::TypeScriptParser::new().parse(&file).unwrap();
        assert_eq!(ConstructorOverInjectionRule::new(2).check(&file, &ast).len(), 1);
        assert!(ConstructorOverInjectionRule::new(3).check(&file, &ast).is_empty());
    }
}
