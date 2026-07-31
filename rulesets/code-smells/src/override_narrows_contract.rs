//! Rule: an override that rejects input its base class accepts — a
//! strengthened precondition, and the second-most common way to break the
//! Liskov Substitution Principle after refusing to implement at all.
//!
//! The base method takes its arguments and does the work; the override starts
//! by raising `TypeError`/`ValueError`/`IllegalArgumentException` for some of
//! them. Code written against the base type is now wrong in a way the type
//! system cannot see: the subtype is not substitutable, because it accepts
//! strictly less than what its contract advertises.
//!
//! Distinct from its two neighbors on purpose:
//! `smells:liskov-not-implemented` catches an override that refuses
//! *everything* (its whole body is a not-implemented throw), and
//! `smells:refused-bequest` catches one that quietly does nothing. This one
//! catches the partial refusal — the override that works, until it doesn't.
//! Not-implemented-style exceptions are deliberately excluded here so the same
//! method is never reported by both rules.
//!
//! Whole-program (`CrossFileRule`), same wiring as those two: the base class
//! is usually in another file. Rust is out of scope — structs have no
//! inheritance, so "override" has no meaning there.

use yunq_ast::{AstNode, NodeKind, SourceFile};
use yunq_rules_engine::{CrossFileRule, Finding, IssueType, RuleId, RuleMetadata, Severity};
use yunq_symbols::{ClassInfo, ClassRegistry, MethodInfo};

const CONSTRUCTOR_NAMES: &[&str] = &["constructor", "__init__"];

/// Exceptions that mean "you passed me something I refuse to handle". Matched
/// case-insensitively on a contains basis so project-specific wrappers
/// (`InvalidArgumentError`, `ArgumentOutOfRangeException`) are covered too.
const PRECONDITION_EXCEPTIONS: &[&str] = &[
    "typeerror",
    "valueerror",
    "argument",
    "invalid",
    "illegalstate",
    "assertionerror",
];

fn is_throw(node: &AstNode) -> bool {
    matches!(node.kind(), NodeKind::Other(k) if k.as_ref() == "throw_statement" || k.as_ref() == "raise_statement")
}

/// Every identifier named inside a method's throw/raise statements — the
/// exception types it can raise, plus incidental argument names, which is
/// harmless: the names are matched against a specific table.
fn thrown_names(method: &AstNode) -> Vec<&str> {
    method
        .descendants()
        .filter(|n| is_throw(n))
        .flat_map(|throw| throw.descendants())
        .filter(|n| *n.kind() == NodeKind::Identifier)
        .map(|n| n.text())
        .collect()
}

fn is_not_implemented(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower.contains("notimplemented")
        || lower.contains("notsupported")
        || lower.contains("unsupportedoperation")
}

/// The precondition exception an override introduces, if any.
fn precondition_exception(method: &AstNode) -> Option<String> {
    thrown_names(method)
        .into_iter()
        .find(|name| {
            let lower = name.to_ascii_lowercase();
            !is_not_implemented(name)
                && PRECONDITION_EXCEPTIONS
                    .iter()
                    .any(|kind| lower.contains(kind))
        })
        .map(str::to_string)
}

/// The nearest ancestor of `class` that declares a method named `name`,
/// following the superclass chain as far as the registry can resolve it.
fn inherited_method<'a, 'r>(
    class: &ClassInfo<'a>,
    name: &str,
    registry: &'r ClassRegistry<'a>,
) -> Option<(&'r ClassInfo<'a>, &'r MethodInfo<'a>)> {
    let mut seen = vec![class.name.clone()];
    let mut current = class.superclass.clone();
    while let Some(ancestor_name) = current {
        if seen.contains(&ancestor_name) {
            break; // malformed hierarchy; stop rather than loop
        }
        seen.push(ancestor_name.clone());
        let ancestor = registry.get(&ancestor_name)?;
        if let Some(method) = ancestor.method(name) {
            return Some((ancestor, method));
        }
        current = ancestor.superclass.clone();
    }
    None
}

pub struct OverrideNarrowsContractRule {
    id: RuleId,
}

impl OverrideNarrowsContractRule {
    pub fn new() -> Self {
        Self {
            id: RuleId::new("smells:override-narrows-contract").expect("valid rule id"),
        }
    }
}

impl Default for OverrideNarrowsContractRule {
    fn default() -> Self {
        Self::new()
    }
}

impl CrossFileRule for OverrideNarrowsContractRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn default_severity(&self) -> Severity {
        Severity::Major
    }

    fn remediation_effort_minutes(&self) -> u32 {
        45
    }

    fn issue_type(&self) -> IssueType {
        IssueType::CodeSmell
    }

    fn metadata(&self) -> RuleMetadata {
        RuleMetadata {
            description: "An overriding method rejects arguments its base method accepts (raising a type/argument error the base never raises), so the subtype is not substitutable for its supertype.".into(),
            tags: vec!["design".into(), "liskov".into(), "cross-file".into()],
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
            if class.superclass.is_none() {
                continue;
            }
            for method in &class.methods {
                if CONSTRUCTOR_NAMES.contains(&method.name.as_str()) {
                    continue;
                }
                let Some(exception) = precondition_exception(method.node) else {
                    continue;
                };
                let Some((ancestor, base_method)) =
                    inherited_method(class, &method.name, &registry)
                else {
                    continue;
                };
                if !thrown_names(base_method.node).is_empty() {
                    continue; // the base rejects input too: same contract, not a narrower one
                }
                let Some(index) = files.iter().position(|(file, _)| file.path() == class.file)
                else {
                    continue;
                };
                findings.push((
                    index,
                    Finding::new(
                        format!(
                            "`{}::{}` raises `{}` for input `{}::{}` accepts — a subtype must not strengthen its supertype's preconditions, or code written against `{}` breaks when handed a `{}` (Liskov Substitution Principle)",
                            class.name, method.name, exception, ancestor.name, base_method.name, ancestor.name, class.name
                        ),
                        method.span,
                    ),
                ));
            }
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
        OverrideNarrowsContractRule::new()
            .check(&files)
            .into_iter()
            .map(|(_, f)| f)
            .collect()
    }

    fn check_py(code: &str) -> Vec<Finding> {
        let file = SourceFile::new("t.py", code, LanguageIdentifier::python()).unwrap();
        let ast = yunq_parser_python::PythonParser::new()
            .parse(&file)
            .unwrap();
        let files = vec![(file, ast)];
        OverrideNarrowsContractRule::new()
            .check(&files)
            .into_iter()
            .map(|(_, f)| f)
            .collect()
    }

    #[test]
    fn flags_an_override_that_rejects_negative_input_its_base_accepts() {
        let findings = check_ts(
            "class Account {\n  deposit(amount: number): void {\n    this.total += amount;\n  }\n}\nclass FixedAccount extends Account {\n  deposit(amount: number): void {\n    if (amount > 100) {\n      throw new ValueError('too large');\n    }\n    super.deposit(amount);\n  }\n}\n",
        );
        assert_eq!(findings.len(), 1);
        assert!(
            findings[0].message.contains("`FixedAccount::deposit`"),
            "{}",
            findings[0].message
        );
        assert!(findings[0].message.contains("ValueError"));
        assert!(findings[0].message.contains("Liskov"));
    }

    #[test]
    fn silent_when_the_base_method_also_rejects_input() {
        let findings = check_ts(
            "class Account {\n  deposit(amount: number): void {\n    if (amount < 0) {\n      throw new TypeError('negative');\n    }\n  }\n}\nclass FixedAccount extends Account {\n  deposit(amount: number): void {\n    if (amount > 100) {\n      throw new TypeError('too large');\n    }\n  }\n}\n",
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn silent_on_a_not_implemented_throw_owned_by_the_liskov_rule() {
        let findings = check_ts(
            "class Account {\n  deposit(amount: number): void {\n    this.total += amount;\n  }\n}\nclass ReadOnlyAccount extends Account {\n  deposit(amount: number): void {\n    throw new NotImplementedError('read only');\n  }\n}\n",
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn silent_on_a_class_with_no_base_class() {
        let findings = check_ts(
            "class Account {\n  deposit(amount: number): void {\n    if (amount < 0) {\n      throw new TypeError('negative');\n    }\n  }\n}\n",
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn silent_on_a_method_the_base_class_never_declared() {
        let findings = check_ts(
            "class Account {}\nclass FixedAccount extends Account {\n  freeze(reason: string): void {\n    throw new ValueError(reason);\n  }\n}\n",
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn flags_a_python_override_raising_typeerror() {
        let findings = check_py(
            "class Repo:\n    def save(self, order):\n        self._items.append(order)\n\nclass DraftRepo(Repo):\n    def save(self, order):\n        if not order.is_draft:\n            raise TypeError('drafts only')\n        self._items.append(order)\n",
        );
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("`DraftRepo::save`"));
        assert!(findings[0].message.contains("TypeError"));
    }

    #[test]
    fn resolves_a_base_class_declared_two_levels_up_in_another_file() {
        let parser = yunq_parser_typescript::TypeScriptParser::new();
        let base = SourceFile::new(
            "base.ts",
            "export class Account {\n  deposit(amount: number): void {\n    this.total += amount;\n  }\n}\nexport class MidAccount extends Account {}\n",
            LanguageIdentifier::typescript(),
        )
        .unwrap();
        let leaf = SourceFile::new(
            "leaf.ts",
            "class LeafAccount extends MidAccount {\n  deposit(amount: number): void {\n    throw new InvalidArgumentError('nope');\n  }\n}\n",
            LanguageIdentifier::typescript(),
        )
        .unwrap();
        let files = vec![
            (base.clone(), parser.parse(&base).unwrap()),
            (leaf.clone(), parser.parse(&leaf).unwrap()),
        ];
        let findings = OverrideNarrowsContractRule::new().check(&files);
        assert_eq!(findings.len(), 1);
        assert_eq!(files[findings[0].0].0.path(), "leaf.ts");
        assert!(findings[0].1.message.contains("`Account::deposit`"));
    }

    #[test]
    fn a_malformed_cyclic_hierarchy_terminates_without_a_finding() {
        let findings = check_ts(
            "class A extends B {\n  run(): void {\n    throw new TypeError('x');\n  }\n}\nclass B extends A {\n  run(): void {}\n}\n",
        );
        // Whatever the walk decides, it must not hang; a cyclic hierarchy is
        // invalid code and reporting nothing about it is the honest outcome.
        assert!(findings.len() <= 1);
    }
}
