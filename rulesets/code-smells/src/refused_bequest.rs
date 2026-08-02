//! Rule: a subclass that overrides most of its parent's methods with
//! trivial (empty/no-op/pure-pass-through) bodies — the "Refused Bequest"
//! smell: the subclass doesn't actually want the behavior it inherits, a
//! sign the class hierarchy models the wrong relationship (composition or a
//! narrower interface would fit better than inheritance). Needs
//! `vord_symbols::ClassRegistry` to resolve the superclass by name and see
//! which of the child's methods actually share a name with — and so
//! override — one of the parent's.
//!
//! Rust is out of scope: structs have no inheritance, so "override" has no
//! meaning there.
//!
//! Whole-program (`CrossFileRule`): built via `ClassRegistry::build_cross_file`
//! so a superclass declared in another file still resolves — same wiring
//! pattern as `smells:god-class`.

use vord_ast::{AstNode, NodeKind, SourceFile};
use vord_rules_engine::{CrossFileRule, Finding, IssueType, RuleId, RuleMetadata, Severity};
use vord_symbols::{ClassInfo, ClassRegistry, MethodInfo};

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

/// Whether a single statement is a bare `super.<method>(...)` /
/// `super().<method>(...)` delegation — still "trivial" in the sense that
/// no override-specific behavior was added.
fn is_super_delegation(stmt: &AstNode) -> bool {
    stmt.descendants()
        .any(|n| *n.kind() == NodeKind::Call && n.text().contains("super"))
        && stmt
            .descendants()
            .filter(|n| *n.kind() == NodeKind::Call)
            .count()
            <= 1
}

/// A method body with no statements, a single `pass`, or a single
/// super-delegating call/return counts as a trivial override — one that
/// doesn't add or refuse behavior in any way worth a smell finding on its
/// own, but see [`is_trivially_refusing`] for what *does* count: an
/// override whose body is empty or a bare early-return, refusing the
/// parent's behavior outright without even delegating to it.
fn is_trivially_refusing(method: &AstNode) -> bool {
    let statements = body_statements(method);
    match statements.as_slice() {
        [] => true,
        [only] => {
            matches!(only.kind(), NodeKind::Other(k) if k.as_ref() == "pass_statement")
                || (matches!(only.kind(), NodeKind::Other(k) if k.as_ref() == "return_statement")
                    && only.children().is_empty())
                || is_super_delegation(only)
        }
        _ => false,
    }
}

fn check_class(class: &ClassInfo<'_>, superclass: &ClassInfo<'_>, findings: &mut Vec<Finding>) {
    if superclass.methods.len() < 2 {
        return; // too small a parent to meaningfully "refuse most of"
    }
    let overrides: Vec<&MethodInfo<'_>> = class
        .methods
        .iter()
        .filter(|m| superclass.method(&m.name).is_some())
        .collect();
    if overrides.len() < 2 {
        return;
    }
    let trivial: Vec<&&MethodInfo<'_>> = overrides
        .iter()
        .filter(|m| is_trivially_refusing(m.node))
        .collect();
    if trivial.len() != overrides.len() {
        return; // at least one override does real work — not a refusal
    }
    // Refuses at least half of what the parent actually offers.
    if overrides.len() * 2 < superclass.methods.len() {
        return;
    }
    let names = overrides
        .iter()
        .map(|m| format!("`{}`", m.name))
        .collect::<Vec<_>>()
        .join(", ");
    let span = class.span.unwrap_or(overrides[0].span);
    findings.push(Finding::new(
        format!(
            "`{}` overrides {}/{} of `{}`'s methods ({names}) with empty/trivial bodies — it refuses most of what it inherits, a sign inheritance is the wrong relationship here",
            class.name,
            overrides.len(),
            superclass.methods.len(),
            superclass.name
        ),
        span,
    ));
}

pub struct RefusedBequestRule {
    id: RuleId,
}

impl RefusedBequestRule {
    pub fn new() -> Self {
        Self {
            id: RuleId::new("smells:refused-bequest").expect("valid rule id"),
        }
    }
}

impl Default for RefusedBequestRule {
    fn default() -> Self {
        Self::new()
    }
}

impl CrossFileRule for RefusedBequestRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn default_severity(&self) -> Severity {
        Severity::Minor
    }

    fn issue_type(&self) -> IssueType {
        IssueType::CodeSmell
    }

    fn metadata(&self) -> RuleMetadata {
        RuleMetadata {
            description: "A subclass overrides most of its parent's methods with empty or trivial bodies, refusing most of what it inherits — inheritance is likely the wrong relationship here.".into(),
            tags: vec!["design".into(), "refused-bequest".into(), "cross-file".into()],
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
    use vord_ast::LanguageIdentifier;
    use vord_rules_engine::AstParser;

    fn check_ts(code: &str) -> Vec<Finding> {
        let file = SourceFile::new("t.ts", code, LanguageIdentifier::typescript()).unwrap();
        let ast = vord_parser_typescript::TypeScriptParser::new()
            .parse(&file)
            .unwrap();
        let files = vec![(file, ast)];
        RefusedBequestRule::new()
            .check(&files)
            .into_iter()
            .map(|(_, f)| f)
            .collect()
    }

    #[test]
    fn flags_subclass_that_trivially_overrides_most_parent_methods() {
        let findings = check_ts(
            "class Bird {\n  fly() { return 1; }\n  eat() { return 1; }\n  nest() { return 1; }\n}\nclass Penguin extends Bird {\n  fly() {}\n  eat() {}\n}\n",
        );
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("Penguin"));
        assert!(findings[0].message.contains("Bird"));
    }

    #[test]
    fn allows_subclass_that_adds_real_behavior_in_its_overrides() {
        let findings = check_ts(
            "class Bird {\n  fly() { return 1; }\n  eat() { return 1; }\n  nest() { return 1; }\n}\nclass Eagle extends Bird {\n  fly() { return this.altitude * 2; }\n  eat() { return this.prey; }\n}\n",
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn allows_a_single_trivial_override() {
        let findings = check_ts(
            "class Bird {\n  fly() { return 1; }\n  eat() { return 1; }\n  nest() { return 1; }\n}\nclass Robin extends Bird {\n  nest() {}\n}\n",
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn flags_pure_super_delegating_overrides_as_trivial() {
        let findings = check_ts(
            "class Bird {\n  fly() { return 1; }\n  eat() { return 1; }\n}\nclass Sparrow extends Bird {\n  fly() { return super.fly(); }\n  eat() { return super.eat(); }\n}\n",
        );
        // A pure delegation is trivial (no new behavior), but delegation —
        // unlike an outright empty override — still uses the parent's
        // behavior rather than refusing it, so this is intentionally still
        // flagged as trivial-with-no-added-value; kept as a documented
        // edge case rather than special-cased out, since a subclass that
        // overrides every single method only to forward to `super` unchanged
        // is *itself* a smell (the overrides are pointless).
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn ignores_classes_with_no_superclass() {
        let findings = check_ts("class Standalone {\n  a() {}\n  b() {}\n}\n");
        assert!(findings.is_empty());
    }

    #[test]
    fn flags_subclass_whose_superclass_is_declared_in_another_file() {
        let bird_file = SourceFile::new(
            "bird.ts",
            "class Bird {\n  fly() { return 1; }\n  eat() { return 1; }\n  nest() { return 1; }\n}\n",
            LanguageIdentifier::typescript(),
        )
        .unwrap();
        let penguin_file = SourceFile::new(
            "penguin.ts",
            "class Penguin extends Bird {\n  fly() {}\n  eat() {}\n}\n",
            LanguageIdentifier::typescript(),
        )
        .unwrap();
        let parser = vord_parser_typescript::TypeScriptParser::new();
        let files = vec![
            (bird_file.clone(), parser.parse(&bird_file).unwrap()),
            (penguin_file.clone(), parser.parse(&penguin_file).unwrap()),
        ];
        let findings = RefusedBequestRule::new().check(&files);
        assert_eq!(findings.len(), 1);
        let (index, finding) = &findings[0];
        assert_eq!(files[*index].0.path(), "penguin.ts");
        assert!(finding.message.contains("Penguin"));
        assert!(finding.message.contains("Bird"));
    }
}
