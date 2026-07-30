//! Rule: a class coupled to too many other classes in the same codebase —
//! Coupling Between Objects (CBO) restricted to *source* coupling, i.e. types
//! this project declares itself.
//!
//! This is the Single Responsibility Principle measured by reach rather than
//! by size: `smells:god-class` counts what a class *has* (methods, fields) and
//! `smells:low-cohesion` counts how its own members clump, but a class can
//! pass both while touching forty other types, and that class is still the one
//! nothing can change around.
//!
//! The metric is CodeQL's `TEfferentSourceCoupling.ql` (outgoing dependencies
//! restricted to types with source), thresholded the way `java/hub-class`
//! thresholds it — CodeQL fires at 15 outgoing *and* 15 incoming; SonarQube's
//! S1200 ("classes should not be coupled to too many other classes", filed
//! under the Single Responsibility Principle) defaults to 20 outgoing alone.
//! This rule takes SonarQube's direction (outgoing only, so a widely-used type
//! is not punished for being useful) at CodeQL's spirit of counting only types
//! the project owns.
//!
//! Whole-program (`CrossFileRule`): "how many *locally defined* classes does
//! this one reach" is exactly the question `ClassRegistry::build_cross_file`
//! answers, and the same question is meaningless per-file — a service and the
//! ports it uses are almost never in one file.

use std::collections::BTreeSet;

use yunq_ast::{AstNode, NodeKind, SourceFile};
use yunq_rules_engine::{CrossFileRule, Finding, IssueType, RuleId, RuleMetadata, Severity};
use yunq_symbols::{ClassInfo, ClassRegistry};

/// Every locally-defined class `class` depends on: its superclass, the types
/// of its fields and method parameters, and every name its method bodies
/// mention that resolves to another class in the registry.
fn referenced_classes(class: &ClassInfo<'_>, registry: &ClassRegistry<'_>) -> BTreeSet<String> {
    let mut referenced = BTreeSet::new();
    let mut record = |name: &str| {
        if name != class.name && registry.get(name).is_some() {
            referenced.insert(name.to_string());
        }
    };

    if let Some(superclass) = &class.superclass {
        record(superclass);
    }
    for field in &class.fields {
        for name in type_names(field.declared_type.as_deref()) {
            record(&name);
        }
    }
    for method in &class.methods {
        for param in &method.params {
            for name in type_names(param.declared_type.as_deref()) {
                record(&name);
            }
        }
        for node in method.node.descendants().filter(|n| *n.kind() == NodeKind::Identifier) {
            record(node.text());
        }
    }
    referenced
}

/// The identifiers inside a declared type, so `Map<string, Order>` counts as
/// a reference to `Order`. Non-class names are filtered by the registry
/// lookup at the call site, so no primitive table is needed here.
fn type_names(declared: Option<&str>) -> Vec<String> {
    let Some(declared) = declared else { return Vec::new() };
    declared
        .split(|c: char| !c.is_alphanumeric() && c != '_')
        .filter(|part| !part.is_empty())
        .map(str::to_string)
        .collect()
}

pub struct ClassFanOutRule {
    id: RuleId,
    max_dependencies: usize,
}

impl ClassFanOutRule {
    pub fn new(max_dependencies: usize) -> Self {
        Self { id: RuleId::new("smells:class-fan-out").expect("valid rule id"), max_dependencies }
    }
}

impl Default for ClassFanOutRule {
    fn default() -> Self {
        Self::new(20)
    }
}

impl CrossFileRule for ClassFanOutRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn default_severity(&self) -> Severity {
        Severity::Major
    }

    fn remediation_effort_minutes(&self) -> u32 {
        120
    }

    fn issue_type(&self) -> IssueType {
        IssueType::CodeSmell
    }

    fn metadata(&self) -> RuleMetadata {
        RuleMetadata {
            description: "A class depends on more of the project's own classes than one responsibility needs (coupling between objects), so almost any change in the codebase can reach it.".into(),
            tags: vec!["design".into(), "single-responsibility".into(), "coupling".into(), "cross-file".into()],
            cwe: None,
            produces_hotspots: false,
        }
    }

    fn check(&self, files: &[(SourceFile, AstNode)]) -> Vec<(usize, Finding)> {
        let views: Vec<(&str, &AstNode)> = files
            .iter()
            .filter(|(file, _)| !yunq_rules_engine::is_test_only_path(file.path()))
            .map(|(file, ast)| (file.path(), ast))
            .collect();
        let registry = ClassRegistry::build_cross_file(&views);
        let mut findings = Vec::new();
        for class in registry.iter() {
            let dependencies = referenced_classes(class, &registry);
            if dependencies.len() <= self.max_dependencies {
                continue;
            }
            let Some(index) = files.iter().position(|(file, _)| file.path() == class.file) else { continue };
            let Some(span) = class.span else { continue };
            findings.push((
                index,
                Finding::new(
                    format!(
                        "`{}` is coupled to {} other classes in this codebase — a class with that reach is a change amplifier; split it along the clusters of collaborators it actually uses together (Single Responsibility Principle)",
                        class.name,
                        dependencies.len()
                    ),
                    span,
                ),
            ));
        }
        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use yunq_ast::LanguageIdentifier;
    use yunq_rules_engine::AstParser;

    /// A class whose constructor takes `count` distinct declared collaborators,
    /// each of them a real class in the same file.
    fn service_with_collaborators(count: usize) -> String {
        let mut code = String::new();
        for index in 0..count {
            code.push_str(&format!("class Dep{index} {{}}\n"));
        }
        code.push_str("class Service {\n");
        let params: Vec<String> = (0..count).map(|index| format!("d{index}: Dep{index}")).collect();
        code.push_str(&format!("  constructor({}) {{}}\n", params.join(", ")));
        code.push_str("}\n");
        code
    }

    fn check_ts(code: &str) -> Vec<Finding> {
        let file = SourceFile::new("t.ts", code, LanguageIdentifier::typescript()).unwrap();
        let ast = yunq_parser_typescript::TypeScriptParser::new().parse(&file).unwrap();
        let files = vec![(file, ast)];
        ClassFanOutRule::default().check(&files).into_iter().map(|(_, f)| f).collect()
    }

    #[test]
    fn flags_a_class_coupled_to_more_than_twenty_others() {
        let findings = check_ts(&service_with_collaborators(21));
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("`Service` is coupled to 21"), "{}", findings[0].message);
    }

    #[test]
    fn allows_a_class_at_the_threshold() {
        assert!(check_ts(&service_with_collaborators(20)).is_empty());
    }

    #[test]
    fn counts_a_class_once_however_many_times_it_is_mentioned() {
        let code = "class Dep {}\nclass Service {\n  a: Dep;\n  b: Dep;\n  use(d: Dep): Dep {\n    return new Dep();\n  }\n}\n";
        let findings = ClassFanOutRule::new(1).check(&{
            let file = SourceFile::new("t.ts", code, LanguageIdentifier::typescript()).unwrap();
            let ast = yunq_parser_typescript::TypeScriptParser::new().parse(&file).unwrap();
            vec![(file, ast)]
        });
        assert!(findings.is_empty(), "one distinct dependency, mentioned four times: {findings:?}");
    }

    #[test]
    fn counts_dependencies_declared_in_other_files() {
        let parser = yunq_parser_typescript::TypeScriptParser::new();
        let dep_code = "export class DepA {}\nexport class DepB {}\n";
        let service_code = "class Service {\n  constructor(a: DepA, b: DepB) {}\n}\n";
        let dep_file = SourceFile::new("deps.ts", dep_code, LanguageIdentifier::typescript()).unwrap();
        let service_file = SourceFile::new("service.ts", service_code, LanguageIdentifier::typescript()).unwrap();
        let files = vec![
            (dep_file.clone(), parser.parse(&dep_file).unwrap()),
            (service_file.clone(), parser.parse(&service_file).unwrap()),
        ];
        let findings = ClassFanOutRule::new(1).check(&files);
        assert_eq!(findings.len(), 1);
        assert_eq!(files[findings[0].0].0.path(), "service.ts");
        assert!(findings[0].1.message.contains("coupled to 2"));
    }

    #[test]
    fn ignores_names_that_are_not_classes_at_all() {
        let code = "class Service {\n  run(): void {\n    console.log(JSON.stringify(Math.max(1, 2)));\n  }\n}\n";
        assert!(ClassFanOutRule::new(0)
            .check(&{
                let file = SourceFile::new("t.ts", code, LanguageIdentifier::typescript()).unwrap();
                let ast = yunq_parser_typescript::TypeScriptParser::new().parse(&file).unwrap();
                vec![(file, ast)]
            })
            .is_empty());
    }

    #[test]
    fn counts_python_collaborators() {
        let file = SourceFile::new(
            "t.py",
            "class DepA:\n    pass\n\nclass DepB:\n    pass\n\nclass Service:\n    def run(self):\n        return DepA(), DepB()\n",
            LanguageIdentifier::python(),
        )
        .unwrap();
        let ast = yunq_parser_python::PythonParser::new().parse(&file).unwrap();
        let findings = ClassFanOutRule::new(1).check(&[(file, ast)]);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].1.message.contains("`Service`"));
    }

    #[test]
    fn counts_rust_struct_collaborators_across_impl_blocks() {
        let file = SourceFile::new(
            "t.rs",
            "pub struct DepA;\npub struct DepB;\npub struct Service {\n    a: DepA,\n}\n\nimpl Service {\n    fn run(&self, b: DepB) {}\n}\n",
            LanguageIdentifier::rust(),
        )
        .unwrap();
        let ast = yunq_parser_rust::RustParser::new().parse(&file).unwrap();
        let findings = ClassFanOutRule::new(1).check(&[(file, ast)]);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].1.message.contains("`Service` is coupled to 2"));
    }

    #[test]
    fn test_files_neither_report_nor_inflate_counts() {
        let parser = yunq_parser_typescript::TypeScriptParser::new();
        let prod = SourceFile::new(
            "service.ts",
            "class DepA {}\nclass Service {\n  constructor(a: DepA) {}\n}\n",
            LanguageIdentifier::typescript(),
        )
        .unwrap();
        let test = SourceFile::new(
            "tests/service.test.ts",
            "class FakeA {}\nclass FakeB {}\nclass Harness {\n  constructor(a: FakeA, b: FakeB) {}\n}\n",
            LanguageIdentifier::typescript(),
        )
        .unwrap();
        let files =
            vec![(prod.clone(), parser.parse(&prod).unwrap()), (test.clone(), parser.parse(&test).unwrap())];
        let findings = ClassFanOutRule::new(1).check(&files);
        assert!(findings.is_empty(), "{findings:?}");
    }
}
