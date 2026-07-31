//! Rule: an overridden method whose entire body throws/raises a
//! Not-Implemented/Not-Supported style exception — the Liskov Substitution
//! smell: client code written against the superclass's contract expects this
//! method to behave, but a caller that substitutes this subclass in gets an
//! exception instead, breaking substitutability outright rather than just
//! refusing behavior quietly (the milder `smells:refused-bequest` case).
//! Reuses `yunq_symbols::ClassRegistry` — same wiring as
//! `smells:refused-bequest`.
//!
//! Rust is out of scope: structs have no inheritance, so "override" has no
//! meaning there.

use yunq_ast::{AstNode, NodeKind, SourceFile};
use yunq_rules_engine::{CrossFileRule, Finding, IssueType, RuleId, RuleMetadata, Severity};
use yunq_symbols::{ClassInfo, ClassRegistry};

/// The method body's statement list: TS's `statement_block`, Python's
/// `block`.
fn body_statements(method: &AstNode) -> Vec<&AstNode> {
    method
        .children()
        .iter()
        .find(|c| matches!(c.kind(), NodeKind::Other(k) if k.as_ref() == "statement_block" || k.as_ref() == "block"))
        .map(|b| b.children().iter().collect())
        .unwrap_or_default()
}

/// The exception constructor name a `throw new Foo(...)` / `raise Foo(...)`
/// statement invokes.
fn thrown_exception_name(stmt: &AstNode) -> Option<&str> {
    let call = stmt.first_child().filter(|c| *c.kind() == NodeKind::Call)?;
    let callee = call
        .first_child()
        .filter(|c| *c.kind() == NodeKind::Identifier)?;
    Some(callee.text())
}

fn is_not_implemented_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower.contains("notimplemented")
        || lower.contains("notsupported")
        || lower.contains("unsupportedoperation")
}

/// Whether `method`'s entire body is a single throw/raise of a
/// not-implemented/not-supported exception.
fn is_not_implemented_throw(method: &AstNode) -> bool {
    match body_statements(method).as_slice() {
        [only] => {
            matches!(only.kind(), NodeKind::Other(k) if k.as_ref() == "throw_statement" || k.as_ref() == "raise_statement")
                && thrown_exception_name(only).is_some_and(is_not_implemented_name)
        }
        _ => false,
    }
}

fn check_class(class: &ClassInfo<'_>, superclass: &ClassInfo<'_>, findings: &mut Vec<Finding>) {
    for method in &class.methods {
        if superclass.method(&method.name).is_none() {
            continue; // not an override — a new method the parent never promised
        }
        if is_not_implemented_throw(method.node) {
            findings.push(Finding::new(
                format!(
                    "`{}::{}` overrides `{}`'s method only to throw a not-implemented exception — code written against `{}`'s contract will crash when it substitutes `{}` in, instead of getting the behavior the contract promised (Liskov Substitution Principle)",
                    class.name, method.name, superclass.name, superclass.name, class.name
                ),
                method.span,
            ));
        }
    }
}

pub struct LiskovNotImplementedRule {
    id: RuleId,
}

impl LiskovNotImplementedRule {
    pub fn new() -> Self {
        Self {
            id: RuleId::new("smells:liskov-not-implemented").expect("valid rule id"),
        }
    }
}

impl Default for LiskovNotImplementedRule {
    fn default() -> Self {
        Self::new()
    }
}

impl CrossFileRule for LiskovNotImplementedRule {
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
            description: "An overridden method's entire body throws/raises a not-implemented or not-supported exception — callers that substitute this subclass for its parent will crash where the parent's contract promised behavior.".into(),
            tags: vec!["design".into(), "liskov-substitution".into(), "cross-file".into()],
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
            let Some(superclass_name) = &class.superclass else {
                continue;
            };
            let Some(superclass) = registry.get(superclass_name) else {
                continue;
            };
            let Some(index) = files.iter().position(|(file, _)| file.path() == class.file) else {
                continue;
            };
            let mut plain = Vec::new();
            check_class(class, superclass, &mut plain);
            findings.extend(plain.into_iter().map(|f| (index, f)));
        }
        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use yunq_ast::LanguageIdentifier;
    use yunq_rules_engine::AstParser;

    fn check_ts(code: &str) -> Vec<Finding> {
        let file = SourceFile::new("t.ts", code, LanguageIdentifier::typescript()).unwrap();
        let ast = yunq_parser_typescript::TypeScriptParser::new()
            .parse(&file)
            .unwrap();
        let files = vec![(file, ast)];
        LiskovNotImplementedRule::new()
            .check(&files)
            .into_iter()
            .map(|(_, f)| f)
            .collect()
    }

    #[test]
    fn flags_override_that_throws_not_implemented_error() {
        let findings = check_ts(
            "class Bird {\n  fly() { return 1; }\n}\nclass Penguin extends Bird {\n  fly() { throw new NotImplementedError('penguins cannot fly'); }\n}\n",
        );
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("Penguin::fly"));
        assert!(findings[0].message.contains("Bird"));
    }

    #[test]
    fn flags_override_that_throws_not_supported_exception() {
        let findings = check_ts(
            "class Bird {\n  fly() { return 1; }\n}\nclass Penguin extends Bird {\n  fly() { throw new NotSupportedException(); }\n}\n",
        );
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn allows_override_that_throws_an_unrelated_exception() {
        let findings = check_ts(
            "class Bird {\n  fly() { return 1; }\n}\nclass Penguin extends Bird {\n  fly() { throw new RangeError('bad altitude'); }\n}\n",
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn allows_override_with_real_behavior() {
        let findings = check_ts(
            "class Bird {\n  fly() { return 1; }\n}\nclass Eagle extends Bird {\n  fly() { return this.altitude * 2; }\n}\n",
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn python_raise_not_implemented_error_is_flagged() {
        let file = SourceFile::new(
            "t.py",
            "class Bird:\n    def fly(self):\n        return 1\n\nclass Penguin(Bird):\n    def fly(self):\n        raise NotImplementedError('penguins cannot fly')\n",
            LanguageIdentifier::python(),
        )
        .unwrap();
        let ast = yunq_parser_python::PythonParser::new()
            .parse(&file)
            .unwrap();
        let files = vec![(file, ast)];
        let findings: Vec<Finding> = LiskovNotImplementedRule::new()
            .check(&files)
            .into_iter()
            .map(|(_, f)| f)
            .collect();
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("Penguin::fly"));
    }

    #[test]
    fn ignores_methods_that_are_not_overrides() {
        let findings = check_ts(
            "class Bird {\n  fly() { return 1; }\n}\nclass Penguin extends Bird {\n  waddle() { throw new NotImplementedError(); }\n}\n",
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn flags_subclass_whose_superclass_is_declared_in_another_file() {
        let bird_file = SourceFile::new(
            "bird.ts",
            "class Bird {\n  fly() { return 1; }\n}\n",
            LanguageIdentifier::typescript(),
        )
        .unwrap();
        let penguin_file = SourceFile::new(
            "penguin.ts",
            "class Penguin extends Bird {\n  fly() { throw new NotImplementedError(); }\n}\n",
            LanguageIdentifier::typescript(),
        )
        .unwrap();
        let parser = yunq_parser_typescript::TypeScriptParser::new();
        let files = vec![
            (bird_file.clone(), parser.parse(&bird_file).unwrap()),
            (penguin_file.clone(), parser.parse(&penguin_file).unwrap()),
        ];
        let findings = LiskovNotImplementedRule::new().check(&files);
        assert_eq!(findings.len(), 1);
        let (index, _finding) = &findings[0];
        assert_eq!(files[*index].0.path(), "penguin.ts");
    }
}
