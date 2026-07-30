//! Rule: a dependency fetched from a global singleton or a service locator —
//! `Database.getInstance()`, `Container.resolve('mailer')`,
//! `Registry::global()` — instead of being handed in.
//!
//! The Dependency Inversion Principle's other failure mode. `smells:concrete-
//! dependency` catches the class that *constructs* its collaborator; this one
//! catches the class that *looks it up*, which is worse in one specific way:
//! the dependency does not appear in the constructor, the signature, or the
//! type, so nothing about the class's API says it exists. It cannot be
//! substituted in a test without global setup, and it cannot be reasoned about
//! without reading every method body.
//!
//! Per-file (`Rule`): the pattern is local to the call site — no cross-file
//! resolution would make a `getInstance()` call any more or less of a hidden
//! dependency. The composition root is where lookups belong, and a project
//! that wants them exempted there says so with a `// yunq:ignore`-style
//! suppression or an exclusion glob, the same as any other rule.

use yunq_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use yunq_rules_engine::{Finding, IssueType, Rule, RuleId, RuleMetadata, Severity};

/// Accessor names that mean "give me the one global instance".
const SINGLETON_ACCESSORS: &[&str] =
    &["getInstance", "get_instance", "getDefault", "get_default", "instance", "global", "current"];

/// Names that mean "look a dependency up by key", which only count on a
/// receiver that is itself a locator/container/registry: a bare `.get()` is
/// every map in existence.
const LOOKUP_ACCESSORS: &[&str] = &["get", "resolve", "lookup", "make", "inject"];

const LOCATOR_SUFFIXES: &[&str] = &["Locator", "Container", "Registry", "Injector", "Provider", "Factory"];

/// A callee's `receiver.method` / `Receiver::method` split, whatever the
/// separator: TS `Db.getInstance`, Python `Db.get_instance`, Rust
/// `Db::instance`.
fn receiver_and_method(callee: &AstNode) -> Option<(String, String)> {
    let text = callee.text();
    let segments: Vec<&str> = text.split("::").flat_map(|part| part.split('.')).collect();
    if segments.len() < 2 {
        return None;
    }
    let method = segments[segments.len() - 1].trim();
    let receiver = segments[segments.len() - 2].trim();
    (!method.is_empty() && !receiver.is_empty())
        .then(|| (receiver.to_string(), method.to_string()))
}

/// Whether `receiver` names a type rather than a value: a class/struct name,
/// which is what a static singleton accessor is called on. `this`/`self` and
/// lower-cased locals are ordinary collaborators being used normally.
fn is_type_receiver(receiver: &str) -> bool {
    receiver.chars().next().is_some_and(|c| c.is_uppercase())
}

fn locator_lookup(receiver: &str, method: &str) -> bool {
    LOCATOR_SUFFIXES.iter().any(|suffix| receiver.ends_with(suffix)) && LOOKUP_ACCESSORS.contains(&method)
}

pub struct ServiceLocatorRule {
    id: RuleId,
}

impl ServiceLocatorRule {
    pub fn new() -> Self {
        Self { id: RuleId::new("smells:service-locator").expect("valid rule id") }
    }
}

impl Default for ServiceLocatorRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for ServiceLocatorRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn applies_to(&self, language: &LanguageIdentifier) -> bool {
        *language == LanguageIdentifier::typescript()
            || *language == LanguageIdentifier::python()
            || *language == LanguageIdentifier::rust()
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
            description: "A dependency is pulled from a global singleton or a service locator instead of being injected, hiding it from the type and making the code untestable without global setup.".into(),
            tags: vec!["design".into(), "dependency-inversion".into(), "testability".into()],
            cwe: None,
            produces_hotspots: false,
        }
    }

    fn check(&self, file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        if yunq_rules_engine::is_test_only_path(file.path()) {
            return Vec::new();
        }
        ast.descendants()
            .filter(|n| *n.kind() == NodeKind::Call)
            .filter_map(|call| {
                let callee = call.first_child()?;
                let (receiver, method) = receiver_and_method(callee)?;
                if !is_type_receiver(&receiver) {
                    return None;
                }
                let singleton = SINGLETON_ACCESSORS.contains(&method.as_str());
                if !singleton && !locator_lookup(&receiver, &method) {
                    return None;
                }
                Some(Finding::new(
                    format!(
                        "`{receiver}` is looked up globally via `{method}` instead of being injected — the dependency is invisible in this type's API and cannot be substituted; pass it in at construction (Dependency Inversion Principle)"
                    ),
                    call.span(),
                ))
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use yunq_rules_engine::AstParser;

    fn ts(code: &str) -> Vec<Finding> {
        let file = SourceFile::new("t.ts", code, LanguageIdentifier::typescript()).unwrap();
        let ast = yunq_parser_typescript::TypeScriptParser::new().parse(&file).unwrap();
        ServiceLocatorRule::new().check(&file, &ast)
    }

    fn py(code: &str) -> Vec<Finding> {
        let file = SourceFile::new("t.py", code, LanguageIdentifier::python()).unwrap();
        let ast = yunq_parser_python::PythonParser::new().parse(&file).unwrap();
        ServiceLocatorRule::new().check(&file, &ast)
    }

    fn rs(code: &str) -> Vec<Finding> {
        let file = SourceFile::new("t.rs", code, LanguageIdentifier::rust()).unwrap();
        let ast = yunq_parser_rust::RustParser::new().parse(&file).unwrap();
        ServiceLocatorRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_a_singleton_accessor_inside_a_method() {
        let findings = ts(
            "class OrderService {\n  save(o: Order): void {\n    Database.getInstance().insert(o);\n  }\n}\n",
        );
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("`Database`"), "{}", findings[0].message);
        assert!(findings[0].message.contains("getInstance"));
    }

    #[test]
    fn flags_a_container_resolve_call() {
        let findings = ts("const mailer = ServiceContainer.resolve('mailer');\n");
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("ServiceContainer"));
    }

    #[test]
    fn ignores_an_ordinary_get_on_a_map() {
        assert!(ts("const value = cache.get('key');\nconst other = Cache.get('key');\n").is_empty());
    }

    #[test]
    fn ignores_a_call_on_an_injected_collaborator() {
        assert!(ts(
            "class OrderService {\n  constructor(private readonly db: Db) {}\n  save(o: Order): void {\n    this.db.insert(o);\n  }\n}\n"
        )
        .is_empty());
    }

    #[test]
    fn ignores_a_plain_function_call() {
        assert!(ts("const x = getInstance();\n").is_empty());
    }

    #[test]
    fn flags_a_python_singleton_accessor() {
        let findings = py("class Service:\n    def run(self):\n        Database.get_instance().query()\n");
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("get_instance"));
    }

    #[test]
    fn flags_a_rust_global_accessor() {
        let findings = rs("pub fn run() {\n    let db = Registry::global();\n}\n");
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("`Registry`"));
        assert!(findings[0].message.contains("global"));
    }

    #[test]
    fn ignores_a_rust_associated_constructor() {
        assert!(rs("pub fn run() {\n    let s = Service::new();\n}\n").is_empty());
    }

    #[test]
    fn silent_in_test_only_paths() {
        let file = SourceFile::new(
            "tests/service.ts",
            "Database.getInstance().reset();\n",
            LanguageIdentifier::typescript(),
        )
        .unwrap();
        let ast = yunq_parser_typescript::TypeScriptParser::new().parse(&file).unwrap();
        assert!(ServiceLocatorRule::new().check(&file, &ast).is_empty());
    }

    #[test]
    fn applies_only_to_typescript_python_and_rust() {
        let rule = ServiceLocatorRule::new();
        assert!(rule.applies_to(&LanguageIdentifier::typescript()));
        assert!(rule.applies_to(&LanguageIdentifier::python()));
        assert!(rule.applies_to(&LanguageIdentifier::rust()));
        assert!(!rule.applies_to(&LanguageIdentifier::go()));
    }
}
