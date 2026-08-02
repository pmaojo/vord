//! Rule: a constructor that directly instantiates another concrete,
//! locally-defined class and stores it on a field — the Dependency
//! Inversion smell: the high-level class is now hard-wired to one specific
//! implementation instead of depending on an abstraction supplied by its
//! caller, so no other implementation (a test double, a different backend)
//! can ever be substituted without editing this class's own source.
//!
//! Whole-program (`CrossFileRule`): needs `ClassRegistry::build_cross_file`
//! to tell "a locally-defined class" (worth injecting) apart from a
//! built-in/library call (`new Map()`, `list()`, ...), which resolves to
//! nothing in the registry and is silently allowed.

use vord_ast::{AstNode, NodeKind, SourceFile, Span};
use vord_rules_engine::{CrossFileRule, Finding, IssueType, RuleId, RuleMetadata, Severity};
use vord_symbols::{ClassInfo, ClassRegistry};

const CONSTRUCTOR_NAMES: &[&str] = &["constructor", "__init__"];

/// Every `this.<field> = new <Name>(...)` / `self.<field> = <Name>(...)`
/// direct instantiation inside a constructor body: (field name, callee
/// name, assignment span).
fn direct_instantiations(body: &AstNode) -> Vec<(&str, &str, Span)> {
    let mut found = Vec::new();
    for assignment in body
        .descendants()
        .filter(|n| *n.kind() == NodeKind::Assignment)
    {
        let Some(target) = assignment.first_child() else {
            continue;
        };
        if *target.kind() != NodeKind::MemberAccess {
            continue;
        }
        let mut parts = target.children().iter();
        let Some(base) = parts.next() else { continue };
        if base.text() != "self" && base.text() != "this" {
            continue;
        }
        let Some(field) = parts.next().filter(|n| *n.kind() == NodeKind::Identifier) else {
            continue;
        };
        let Some(value) = assignment
            .children()
            .get(1)
            .filter(|n| *n.kind() == NodeKind::Call)
        else {
            continue;
        };
        let Some(callee) = value
            .first_child()
            .filter(|n| *n.kind() == NodeKind::Identifier)
        else {
            continue;
        };
        found.push((field.text(), callee.text(), assignment.span()));
    }
    found
}

fn check_class(class: &ClassInfo<'_>, registry: &ClassRegistry<'_>, findings: &mut Vec<Finding>) {
    let Some(constructor) = class
        .methods
        .iter()
        .find(|m| CONSTRUCTOR_NAMES.contains(&m.name.as_str()))
    else {
        return;
    };
    for (field, callee, span) in direct_instantiations(constructor.node) {
        if callee == class.name || registry.get(callee).is_none() {
            continue; // self-referential factory, or not a locally-defined class at all
        }
        findings.push(Finding::new(
            format!(
                "`{}`'s constructor hard-instantiates `{callee}` for its `{field}` field instead of receiving it as a parameter — depend on an abstraction injected by the caller instead (Dependency Inversion Principle)",
                class.name
            ),
            span,
        ));
    }
}

pub struct ConcreteDependencyRule {
    id: RuleId,
}

impl ConcreteDependencyRule {
    pub fn new() -> Self {
        Self {
            id: RuleId::new("smells:concrete-dependency").expect("valid rule id"),
        }
    }
}

impl Default for ConcreteDependencyRule {
    fn default() -> Self {
        Self::new()
    }
}

impl CrossFileRule for ConcreteDependencyRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn default_severity(&self) -> Severity {
        Severity::Major
    }

    fn issue_type(&self) -> IssueType {
        IssueType::CodeSmell
    }

    fn metadata(&self) -> RuleMetadata {
        RuleMetadata {
            description: "A constructor directly instantiates another concrete, locally-defined class instead of receiving it as an injected dependency, hard-wiring the caller to one implementation.".into(),
            tags: vec!["design".into(), "dependency-inversion".into(), "cross-file".into()],
            cwe: None,
            produces_hotspots: false,
        }
    }

    fn check(&self, files: &[(SourceFile, AstNode)]) -> Vec<(usize, Finding)> {
        let views: Vec<(&str, &AstNode)> =
            files.iter().map(|(file, ast)| (file.path(), ast)).collect();
        let registry = ClassRegistry::build_cross_file(&views);
        let mut findings = Vec::new();
        for class in registry.iter() {
            let Some(index) = files.iter().position(|(file, _)| file.path() == class.file) else {
                continue;
            };
            let mut plain = Vec::new();
            check_class(class, &registry, &mut plain);
            findings.extend(plain.into_iter().map(|f| (index, f)));
        }
        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vord_ast::LanguageIdentifier;
    use vord_rules_engine::AstParser;

    fn check_ts(code: &str) -> Vec<Finding> {
        let file = SourceFile::new("t.ts", code, LanguageIdentifier::typescript()).unwrap();
        let ast = vord_parser_typescript::TypeScriptParser::new()
            .parse(&file)
            .unwrap();
        let files = vec![(file, ast)];
        ConcreteDependencyRule::new()
            .check(&files)
            .into_iter()
            .map(|(_, f)| f)
            .collect()
    }

    #[test]
    fn flags_constructor_that_hard_instantiates_a_local_class() {
        let findings = check_ts(
            "class Repo {}\nclass Service {\n  repo: Repo;\n  constructor() {\n    this.repo = new Repo();\n  }\n}\n",
        );
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("Service"));
        assert!(findings[0].message.contains("Repo"));
    }

    #[test]
    fn allows_constructor_that_receives_the_dependency_as_a_parameter() {
        let findings = check_ts(
            "class Repo {}\nclass Service {\n  repo: Repo;\n  constructor(repo: Repo) {\n    this.repo = repo;\n  }\n}\n",
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn ignores_instantiation_of_a_builtin_or_unresolvable_type() {
        let findings = check_ts(
            "class Service {\n  cache: Map<string, string>;\n  constructor() {\n    this.cache = new Map();\n  }\n}\n",
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn ignores_self_referential_factory_construction() {
        let findings = check_ts(
            "class Node {\n  child: Node;\n  constructor() {\n    this.child = new Node();\n  }\n}\n",
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn python_init_hard_instantiating_a_local_class_is_flagged() {
        let file = SourceFile::new(
            "t.py",
            "class Repo:\n    pass\n\nclass Service:\n    def __init__(self):\n        self.repo = Repo()\n",
            LanguageIdentifier::python(),
        )
        .unwrap();
        let ast = vord_parser_python::PythonParser::new()
            .parse(&file)
            .unwrap();
        let files = vec![(file, ast)];
        let findings: Vec<Finding> = ConcreteDependencyRule::new()
            .check(&files)
            .into_iter()
            .map(|(_, f)| f)
            .collect();
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("Service"));
        assert!(findings[0].message.contains("Repo"));
    }

    #[test]
    fn flags_when_the_concrete_class_is_declared_in_another_file() {
        let repo_file = SourceFile::new(
            "repo.ts",
            "class Repo {}\n",
            LanguageIdentifier::typescript(),
        )
        .unwrap();
        let service_file = SourceFile::new(
            "service.ts",
            "class Service {\n  repo: Repo;\n  constructor() {\n    this.repo = new Repo();\n  }\n}\n",
            LanguageIdentifier::typescript(),
        )
        .unwrap();
        let parser = vord_parser_typescript::TypeScriptParser::new();
        let files = vec![
            (repo_file.clone(), parser.parse(&repo_file).unwrap()),
            (service_file.clone(), parser.parse(&service_file).unwrap()),
        ];
        let findings = ConcreteDependencyRule::new().check(&files);
        assert_eq!(findings.len(), 1);
        let (index, finding) = &findings[0];
        assert_eq!(files[*index].0.path(), "service.ts");
        assert!(finding.message.contains("Repo"));
    }
}
