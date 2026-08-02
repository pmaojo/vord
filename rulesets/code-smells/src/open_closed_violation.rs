//! Rule: a base class whose own method bodies reference one of its own
//! subclasses by name — the Open/Closed smell: adding a new subtype from now
//! on means editing the base class (another `instanceof`/type-check branch,
//! another `new Subclass()` call) instead of purely extending it via a new
//! subclass, the opposite of "open for extension, closed for modification".
//! Needs `ClassRegistry` to resolve the superclass/subclass relationship —
//! same wiring as `smells:refused-bequest`.
//!
//! Rust is out of scope: `ClassRegistry` never populates `superclass` for a
//! struct (Rust has no inheritance), so no base/subclass relationship to
//! violate exists there.

use std::collections::HashMap;

use vord_ast::{AstNode, NodeKind, SourceFile};
use vord_rules_engine::{CrossFileRule, Finding, IssueType, RuleId, RuleMetadata, Severity};
use vord_symbols::{ClassInfo, ClassRegistry};

fn references_name(body: &AstNode, name: &str) -> bool {
    body.descendants()
        .any(|n| *n.kind() == NodeKind::Identifier && n.text() == name)
}

fn check_class(base: &ClassInfo<'_>, subclasses: &[&ClassInfo<'_>], findings: &mut Vec<Finding>) {
    for method in &base.methods {
        for sub in subclasses {
            if references_name(method.node, &sub.name) {
                findings.push(Finding::new(
                    format!(
                        "`{}::{}` references its own subclass `{}` by name — adding a new subtype now means editing `{}` instead of purely extending it (Open/Closed Principle)",
                        base.name, method.name, sub.name, base.name
                    ),
                    method.span,
                ));
            }
        }
    }
}

pub struct OpenClosedViolationRule {
    id: RuleId,
}

impl OpenClosedViolationRule {
    pub fn new() -> Self {
        Self {
            id: RuleId::new("smells:open-closed-violation").expect("valid rule id"),
        }
    }
}

impl Default for OpenClosedViolationRule {
    fn default() -> Self {
        Self::new()
    }
}

impl CrossFileRule for OpenClosedViolationRule {
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
            description: "A base class's own methods reference one of its subclasses by name, so adding a new subtype requires editing the base class instead of purely extending it.".into(),
            tags: vec!["design".into(), "open-closed".into(), "cross-file".into()],
            cwe: None,
            produces_hotspots: false,
        }
    }

    fn check(&self, files: &[(SourceFile, AstNode)]) -> Vec<(usize, Finding)> {
        let views: Vec<(&str, &AstNode)> =
            files.iter().map(|(file, ast)| (file.path(), ast)).collect();
        let registry = ClassRegistry::build_cross_file(&views);
        let mut subclasses_by_super: HashMap<&str, Vec<&ClassInfo<'_>>> = HashMap::new();
        for class in registry.iter() {
            if let Some(superclass_name) = &class.superclass {
                subclasses_by_super
                    .entry(superclass_name.as_str())
                    .or_default()
                    .push(class);
            }
        }
        let mut findings = Vec::new();
        for class in registry.iter() {
            let Some(subclasses) = subclasses_by_super.get(class.name.as_str()) else {
                continue;
            };
            let Some(index) = files.iter().position(|(file, _)| file.path() == class.file) else {
                continue;
            };
            let mut plain = Vec::new();
            check_class(class, subclasses, &mut plain);
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
        OpenClosedViolationRule::new()
            .check(&files)
            .into_iter()
            .map(|(_, f)| f)
            .collect()
    }

    #[test]
    fn flags_base_class_that_instanceof_checks_a_subclass() {
        let findings = check_ts(
            "class Shape {\n  area(): number {\n    if (this instanceof Circle) {\n      return 1;\n    }\n    return 0;\n  }\n}\nclass Circle extends Shape {}\n",
        );
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("Shape::area"));
        assert!(findings[0].message.contains("Circle"));
    }

    #[test]
    fn flags_base_class_that_constructs_a_subclass() {
        let findings = check_ts(
            "class Shape {\n  clone(): Shape {\n    return new Square();\n  }\n}\nclass Square extends Shape {}\n",
        );
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("Square"));
    }

    #[test]
    fn allows_base_class_with_no_subclass_references() {
        let findings = check_ts(
            "class Shape {\n  area(): number {\n    return 0;\n  }\n}\nclass Circle extends Shape {}\n",
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn allows_a_class_with_no_subclasses_at_all() {
        let findings = check_ts("class Standalone {\n  run(): void {}\n}\n");
        assert!(findings.is_empty());
    }

    #[test]
    fn flags_when_the_subclass_is_declared_in_another_file() {
        let shape_file = SourceFile::new(
            "shape.ts",
            "class Shape {\n  clone(): Shape {\n    return new Square();\n  }\n}\n",
            LanguageIdentifier::typescript(),
        )
        .unwrap();
        let square_file = SourceFile::new(
            "square.ts",
            "class Square extends Shape {}\n",
            LanguageIdentifier::typescript(),
        )
        .unwrap();
        let parser = vord_parser_typescript::TypeScriptParser::new();
        let files = vec![
            (shape_file.clone(), parser.parse(&shape_file).unwrap()),
            (square_file.clone(), parser.parse(&square_file).unwrap()),
        ];
        let findings = OpenClosedViolationRule::new().check(&files);
        assert_eq!(findings.len(), 1);
        let (index, finding) = &findings[0];
        assert_eq!(files[*index].0.path(), "shape.ts");
        assert!(finding.message.contains("Square"));
    }

    #[test]
    fn python_isinstance_check_against_a_subclass_is_flagged() {
        let file = SourceFile::new(
            "t.py",
            "class Shape:\n    def describe(self, other):\n        if isinstance(other, Circle):\n            return 1\n        return 0\n\nclass Circle(Shape):\n    pass\n",
            LanguageIdentifier::python(),
        )
        .unwrap();
        let ast = vord_parser_python::PythonParser::new()
            .parse(&file)
            .unwrap();
        let files = vec![(file, ast)];
        let findings: Vec<Finding> = OpenClosedViolationRule::new()
            .check(&files)
            .into_iter()
            .map(|(_, f)| f)
            .collect();
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("Circle"));
    }
}
