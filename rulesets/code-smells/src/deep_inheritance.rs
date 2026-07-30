//! Rule: a class buried deep in an inheritance hierarchy — Depth of
//! Inheritance Tree (DIT). Every level up is behavior a reader has to hold in
//! their head and a subclass has to keep honoring: past a handful of levels,
//! nobody can say what a method call actually does without walking the chain,
//! and Liskov substitutability becomes impossible to reason about because the
//! contract is spread across six declarations.
//!
//! The metric is CodeQL's `TInheritanceDepth.ql`
//! (`java/inheritance-depth`: "types that are many levels deep in an
//! inheritance hierarchy are difficult to understand") and SonarQube's S110,
//! whose default maximum depth is 5 — the threshold used here.
//!
//! Whole-program (`CrossFileRule`) because a hierarchy is almost never in one
//! file; `ClassRegistry::build_cross_file` resolves each `extends`/base-class
//! link across the whole analyzed set. Rust is out of scope: structs have no
//! inheritance, so `ClassRegistry` never records a superclass for one.

use std::collections::BTreeSet;

use yunq_ast::{AstNode, SourceFile};
use yunq_rules_engine::{CrossFileRule, Finding, IssueType, RuleId, RuleMetadata, Severity};
use yunq_symbols::{ClassInfo, ClassRegistry};

/// The chain of ancestors above `class`, nearest first, stopping at the first
/// name the registry cannot resolve (a framework base class outside the
/// analyzed set — its own depth is unknowable, so it counts as one level and
/// no more).
///
/// A `visited` set makes the walk terminate on a malformed hierarchy: `class A
/// extends B` / `class B extends A` is not valid in any of these languages,
/// but it is perfectly possible to *write*, and a linter that hangs on invalid
/// input is worse than one that reports nothing about it.
fn ancestor_chain<'a>(class: &ClassInfo<'a>, registry: &'a ClassRegistry<'a>) -> Vec<String> {
    let mut chain = Vec::new();
    let mut visited: BTreeSet<String> = BTreeSet::from([class.name.clone()]);
    let mut current = class.superclass.clone();
    while let Some(name) = current {
        if !visited.insert(name.clone()) {
            break;
        }
        chain.push(name.clone());
        current = registry.get(&name).and_then(|parent| parent.superclass.clone());
    }
    chain
}

pub struct DeepInheritanceRule {
    id: RuleId,
    max_depth: usize,
}

impl DeepInheritanceRule {
    pub fn new(max_depth: usize) -> Self {
        Self { id: RuleId::new("smells:deep-inheritance").expect("valid rule id"), max_depth }
    }
}

impl Default for DeepInheritanceRule {
    fn default() -> Self {
        Self::new(5)
    }
}

impl CrossFileRule for DeepInheritanceRule {
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
            description: "A class sits too many levels deep in an inheritance hierarchy, spreading its contract across so many ancestors that neither a reader nor a substitutable subclass can hold it. Prefer composition.".into(),
            tags: vec!["design".into(), "inheritance".into(), "liskov".into(), "cross-file".into()],
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
            let chain = ancestor_chain(class, &registry);
            if chain.len() <= self.max_depth {
                continue;
            }
            let Some(index) = files.iter().position(|(file, _)| file.path() == class.file) else { continue };
            let Some(span) = class.span else { continue };
            findings.push((
                index,
                Finding::new(
                    format!(
                        "`{}` is {} levels deep in an inheritance hierarchy ({}) — its contract is spread across every one of them; prefer composition over another level of inheritance",
                        class.name,
                        chain.len(),
                        chain.join(" -> ")
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

    /// `C0` at the root, each `C{n}` extending `C{n-1}`.
    fn ts_chain(levels: usize) -> String {
        let mut code = String::from("class C0 {}\n");
        for level in 1..=levels {
            code.push_str(&format!("class C{level} extends C{} {{}}\n", level - 1));
        }
        code
    }

    fn check_ts(code: &str) -> Vec<Finding> {
        let file = SourceFile::new("t.ts", code, LanguageIdentifier::typescript()).unwrap();
        let ast = yunq_parser_typescript::TypeScriptParser::new().parse(&file).unwrap();
        let files = vec![(file, ast)];
        DeepInheritanceRule::default().check(&files).into_iter().map(|(_, f)| f).collect()
    }

    #[test]
    fn flags_the_class_that_crosses_the_depth_limit() {
        let findings = check_ts(&ts_chain(6));
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("`C6` is 6 levels deep"), "{}", findings[0].message);
        assert!(findings[0].message.contains("C5 -> C4 -> C3 -> C2 -> C1 -> C0"));
    }

    #[test]
    fn allows_a_hierarchy_at_the_limit() {
        assert!(check_ts(&ts_chain(5)).is_empty());
    }

    #[test]
    fn every_class_past_the_limit_is_reported() {
        let findings = check_ts(&ts_chain(7));
        assert_eq!(findings.len(), 2);
    }

    #[test]
    fn an_unresolvable_base_class_counts_as_one_level() {
        // `Component` is outside the analyzed set: the chain stops there.
        let findings = check_ts("class Widget extends Component {}\n");
        assert!(findings.is_empty());
    }

    #[test]
    fn a_malformed_cyclic_hierarchy_terminates_without_a_finding() {
        let findings = check_ts("class A extends B {}\nclass B extends A {}\n");
        assert!(findings.is_empty());
    }

    #[test]
    fn resolves_ancestors_declared_in_other_files() {
        let parser = yunq_parser_typescript::TypeScriptParser::new();
        let base = SourceFile::new(
            "base.ts",
            "export class C0 {}\nexport class C1 extends C0 {}\nexport class C2 extends C1 {}\n",
            LanguageIdentifier::typescript(),
        )
        .unwrap();
        let leaf = SourceFile::new(
            "leaf.ts",
            "class C3 extends C2 {}\nclass C4 extends C3 {}\nclass C5 extends C4 {}\nclass C6 extends C5 {}\n",
            LanguageIdentifier::typescript(),
        )
        .unwrap();
        let files =
            vec![(base.clone(), parser.parse(&base).unwrap()), (leaf.clone(), parser.parse(&leaf).unwrap())];
        let findings = DeepInheritanceRule::default().check(&files);
        assert_eq!(findings.len(), 1);
        assert_eq!(files[findings[0].0].0.path(), "leaf.ts");
    }

    #[test]
    fn flags_a_deep_python_hierarchy() {
        let mut code = String::from("class C0:\n    pass\n");
        for level in 1..=6 {
            code.push_str(&format!("class C{level}(C{}):\n    pass\n", level - 1));
        }
        let file = SourceFile::new("t.py", code.as_str(), LanguageIdentifier::python()).unwrap();
        let ast = yunq_parser_python::PythonParser::new().parse(&file).unwrap();
        let findings = DeepInheritanceRule::default().check(&[(file, ast)]);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].1.message.contains("`C6`"));
    }

    #[test]
    fn threshold_is_configurable() {
        let file = SourceFile::new("t.ts", ts_chain(3).as_str(), LanguageIdentifier::typescript()).unwrap();
        let ast = yunq_parser_typescript::TypeScriptParser::new().parse(&file).unwrap();
        let files = vec![(file, ast)];
        assert_eq!(DeepInheritanceRule::new(2).check(&files).len(), 1);
        assert!(DeepInheritanceRule::new(3).check(&files).is_empty());
    }
}
