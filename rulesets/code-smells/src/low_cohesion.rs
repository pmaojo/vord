//! Rule: Single Responsibility via LCOM (Lack of Cohesion of Methods) — a
//! class whose methods split into more than one connected component when
//! grouped by "touches the same field" bundles more than one responsibility,
//! even when `smells:god-class`'s raw method/field counts stay under
//! threshold (a class can have a modest method count and still be two
//! unrelated classes glued together). Reuses `vord_symbols::ClassRegistry`
//! for extraction — same wiring as `smells:god-class`/`smells:feature-envy`.

use std::collections::{BTreeMap, BTreeSet};

use vord_ast::{AstNode, NodeKind, SourceFile};
use vord_rules_engine::{CrossFileRule, Finding, IssueType, RuleId, RuleMetadata, Severity};
use vord_symbols::{ClassInfo, ClassRegistry, MethodInfo};

/// Constructors are excluded from the cohesion graph: their whole job is
/// initializing every field at once, so including them would trivially
/// connect every method through the constructor and mask exactly the
/// disconnected-responsibilities problem this rule looks for.
const CONSTRUCTOR_NAMES: &[&str] = &["constructor", "__init__"];

/// The methods whose grouping actually says something about the type's
/// design: not constructors, and not trait obligations.
///
/// A Rust `impl Trait for Type` block's methods are excluded because the
/// trait, not the type, decides they exist. `Rule` requires both
/// `fn id(&self) -> &RuleId` and `fn check(&self, ..) -> Vec<Finding>`, so
/// every rule struct in a codebase ends up with an `id` that touches only
/// the `id` field and a `check` that touches only the matching state —
/// two clusters that share no field, reported as two responsibilities. No
/// refactoring can merge them while still implementing the trait, which is
/// the tell that it was never a design finding. Cohesion is a question
/// about the API a type chose for itself: its inherent `impl` block.
fn cohesion_relevant_methods<'a, 'b>(class: &'b ClassInfo<'a>) -> Vec<&'b MethodInfo<'a>> {
    class
        .methods
        .iter()
        .filter(|m| !CONSTRUCTOR_NAMES.contains(&m.name.as_str()) && !m.is_trait_impl())
        .collect()
}

/// The subset of `field_names` that `method_body` reads or writes via a bare
/// `self.field`/`this.field` access.
fn own_field_accesses<'a>(
    method_body: &AstNode,
    field_names: &BTreeSet<&'a str>,
) -> BTreeSet<&'a str> {
    let mut used = BTreeSet::new();
    for access in method_body
        .descendants()
        .filter(|n| *n.kind() == NodeKind::MemberAccess)
    {
        let Some(base) = access.first_child() else {
            continue;
        };
        if base.text() != "self" && base.text() != "this" {
            continue;
        }
        let Some(prop) = access.children().get(1) else {
            continue;
        };
        if let Some(&name) = field_names.get(prop.text()) {
            used.insert(name);
        }
    }
    used
}

/// Union-find over method indices, merging two methods whenever they share
/// at least one own-field access.
struct UnionFind {
    parent: Vec<usize>,
}

impl UnionFind {
    fn new(n: usize) -> Self {
        Self {
            parent: (0..n).collect(),
        }
    }

    fn find(&mut self, x: usize) -> usize {
        if self.parent[x] != x {
            self.parent[x] = self.find(self.parent[x]);
        }
        self.parent[x]
    }

    fn union(&mut self, a: usize, b: usize) {
        let (ra, rb) = (self.find(a), self.find(b));
        if ra != rb {
            self.parent[ra] = rb;
        }
    }
}

/// Groups `class`'s *stateful* methods into connected components — two
/// methods land in the same group iff there is a chain of methods between
/// them, each pair sharing at least one own-field access. More than one
/// group means the class's methods don't actually cohere around one set of
/// state.
///
/// Methods that touch no field at all are left out of the graph entirely
/// rather than each becoming its own singleton component. A method that
/// reads no state is not evidence that the class bundles two
/// responsibilities — it is a pure helper, a constant, or an interface
/// obligation the type has no choice but to declare. Counting each one as
/// a separate "cluster" made the rule fire on essentially every stateless
/// or nearly-stateless type: a Rust `impl Trait for T` block whose
/// `id`/`applies_to`/`default_severity`/`metadata` methods return
/// constants scored as four disconnected responsibilities, and a cohesive
/// store with a handful of private `fn hash_password`-style helpers scored
/// one cluster per helper. LCOM only has something to say about the
/// methods that actually use the state.
fn method_clusters(class: &ClassInfo<'_>) -> Vec<Vec<String>> {
    let field_names: BTreeSet<&str> = class.fields.iter().map(|f| f.name.as_str()).collect();
    let stateful: Vec<(&MethodInfo<'_>, BTreeSet<&str>)> = cohesion_relevant_methods(class)
        .into_iter()
        .map(|m| {
            let accesses = own_field_accesses(m.node, &field_names);
            (m, accesses)
        })
        .filter(|(_, accesses)| !accesses.is_empty())
        .collect();
    let mut uf = UnionFind::new(stateful.len());
    for i in 0..stateful.len() {
        for j in (i + 1)..stateful.len() {
            if !stateful[i].1.is_disjoint(&stateful[j].1) {
                uf.union(i, j);
            }
        }
    }
    let mut groups: BTreeMap<usize, Vec<String>> = BTreeMap::new();
    for (i, (method, _)) in stateful.iter().enumerate() {
        groups
            .entry(uf.find(i))
            .or_default()
            .push(method.name.clone());
    }
    groups.into_values().collect()
}

pub struct LowCohesionRule {
    id: RuleId,
    min_methods: usize,
    min_fields: usize,
}

impl LowCohesionRule {
    pub fn new(min_methods: usize, min_fields: usize) -> Self {
        Self {
            id: RuleId::new("smells:low-cohesion").expect("valid rule id"),
            min_methods,
            min_fields,
        }
    }
}

impl Default for LowCohesionRule {
    /// Below this many methods or fields there isn't enough shape to
    /// meaningfully judge cohesion — a two-method class isn't a design
    /// problem waiting to happen.
    fn default() -> Self {
        Self::new(4, 2)
    }
}

impl CrossFileRule for LowCohesionRule {
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
            description: "A class's methods split into disconnected clusters that never touch the same field (Lack of Cohesion of Methods) — a sign it bundles more than one responsibility. Split it along the cluster boundaries.".into(),
            tags: vec!["design".into(), "cohesion".into(), "lcom".into(), "cross-file".into()],
            cwe: None,
            produces_hotspots: false,
        }
    }

    fn check(&self, files: &[(SourceFile, AstNode)]) -> Vec<(usize, Finding)> {
        let views: Vec<(&str, &AstNode)> =
            files.iter().map(|(file, ast)| (file.path(), ast)).collect();
        let registry = ClassRegistry::build_cross_file(&views);
        // Per-file `#[cfg(test)]` line ranges, computed once rather than
        // per class. Test doubles are written to satisfy a trait as
        // briefly as possible, so they are the least cohesive types in any
        // codebase by construction — and nobody refactors a fake for
        // single-responsibility. Same test-code exemption the single-file
        // rules already apply; a cross-file rule has to look the file up
        // by path to get at the content.
        let test_ranges: Vec<Vec<(u32, u32)>> = files
            .iter()
            .map(|(file, _)| {
                if vord_rules_engine::is_test_only_path(file.path()) {
                    Vec::new()
                } else {
                    vord_rules_engine::rust_test_module_ranges(file.content())
                }
            })
            .collect();
        registry
            .iter()
            .filter_map(|class| {
                if cohesion_relevant_methods(class).len() < self.min_methods
                    || class.fields.len() < self.min_fields
                {
                    return None;
                }
                let clusters = method_clusters(class);
                if clusters.len() < 2 {
                    return None;
                }
                let span = class.span?;
                let index = files.iter().position(|(file, _)| file.path() == class.file)?;
                if vord_rules_engine::is_test_only_path(&class.file)
                    || vord_rules_engine::in_ranges(&test_ranges[index], span.start_line)
                {
                    return None;
                }
                let described =
                    clusters.iter().map(|c| format!("{{{}}}", c.join(", "))).collect::<Vec<_>>().join(" ");
                Some((
                    index,
                    Finding::new(
                        format!(
                            "`{}` splits into {} disconnected method clusters that never share a field — {described} — a sign it bundles more than one responsibility",
                            class.name,
                            clusters.len()
                        ),
                        span,
                    ),
                ))
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vord_ast::LanguageIdentifier;
    use vord_rules_engine::AstParser;

    fn check_ts(code: &str, min_methods: usize, min_fields: usize) -> Vec<Finding> {
        let file = SourceFile::new("t.ts", code, LanguageIdentifier::typescript()).unwrap();
        let ast = vord_parser_typescript::TypeScriptParser::new()
            .parse(&file)
            .unwrap();
        let files = vec![(file, ast)];
        LowCohesionRule::new(min_methods, min_fields)
            .check(&files)
            .into_iter()
            .map(|(_, f)| f)
            .collect()
    }

    #[test]
    fn flags_a_class_with_two_disjoint_method_clusters() {
        let findings = check_ts(
            "class Mixed {\n  a: number = 0;\n  b: number = 0;\n  incA() { this.a += 1; }\n  readA() { return this.a; }\n  incB() { this.b += 1; }\n  readB() { return this.b; }\n}\n",
            4,
            2,
        );
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("Mixed"));
        assert!(findings[0].message.contains("2 disconnected"));
    }

    #[test]
    fn allows_a_cohesive_class() {
        let findings = check_ts(
            "class Counter {\n  a: number = 0;\n  b: number = 0;\n  inc() { this.a += 1; this.b += 1; }\n  read() { return this.a + this.b; }\n  reset() { this.a = 0; this.b = 0; }\n  double() { return this.a * 2; }\n}\n",
            4,
            2,
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn ignores_classes_below_the_method_threshold() {
        let findings = check_ts(
            "class Mixed {\n  a: number = 0;\n  b: number = 0;\n  incA() { this.a += 1; }\n  incB() { this.b += 1; }\n}\n",
            4,
            2,
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn python_self_attribute_clusters_are_detected() {
        let file = SourceFile::new(
            "t.py",
            "class Mixed:\n    def __init__(self):\n        self.a = 0\n        self.b = 0\n\n    def inc_a(self):\n        self.a += 1\n\n    def read_a(self):\n        return self.a\n\n    def inc_b(self):\n        self.b += 1\n\n    def read_b(self):\n        return self.b\n",
            LanguageIdentifier::python(),
        )
        .unwrap();
        let ast = vord_parser_python::PythonParser::new()
            .parse(&file)
            .unwrap();
        let files = vec![(file, ast)];
        let findings: Vec<Finding> = LowCohesionRule::new(4, 2)
            .check(&files)
            .into_iter()
            .map(|(_, f)| f)
            .collect();
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("Mixed"));
    }

    fn check_rust(code: &str, min_methods: usize, min_fields: usize) -> Vec<Finding> {
        let file = SourceFile::new("t.rs", code, LanguageIdentifier::rust()).unwrap();
        let ast = vord_parser_rust::RustParser::new().parse(&file).unwrap();
        let files = vec![(file, ast)];
        LowCohesionRule::new(min_methods, min_fields)
            .check(&files)
            .into_iter()
            .map(|(_, f)| f)
            .collect()
    }

    #[test]
    fn a_rust_trait_impl_is_not_a_cohesion_finding() {
        // The regression this guards: `Rule` obliges every implementer to
        // provide `id`, `applies_to`, `default_severity` and `check`.
        // `id` touches only the `id` field and `check` only the state it
        // matches on, so LCOM saw two field-disjoint clusters and reported
        // "bundles more than one responsibility" — on all 20 rule structs
        // in this repo at once. There is no way to satisfy the trait *and*
        // make those methods share a field, which is what makes it a
        // false positive rather than a finding anyone could act on.
        let findings = check_rust(
            "struct MyRule {\n    id: RuleId,\n    threshold: usize,\n}\n\
             impl MyRule {\n    fn new() -> Self {\n        Self { id: RuleId::new(), threshold: 10 }\n    }\n}\n\
             impl Rule for MyRule {\n\
             \x20   fn id(&self) -> &RuleId {\n        &self.id\n    }\n\
             \x20   fn applies_to(&self, lang: &Lang) -> bool {\n        true\n    }\n\
             \x20   fn default_severity(&self) -> Severity {\n        Severity::Major\n    }\n\
             \x20   fn check(&self, ast: &AstNode) -> Vec<Finding> {\n        vec![self.threshold]\n    }\n}\n",
            4,
            2,
        );
        assert!(
            findings.is_empty(),
            "trait obligations reported as a design smell: {findings:?}"
        );
    }

    #[test]
    fn stateless_helpers_do_not_each_count_as_their_own_cluster() {
        // A cohesive type whose methods all revolve around one field, plus
        // private helpers that touch no state at all. Each helper used to
        // become its own singleton cluster, so a well-factored type scored
        // worse the more it extracted pure helpers — backwards.
        let findings = check_rust(
            "struct Store {\n    items: Vec<String>,\n    salt: String,\n}\n\
             impl Store {\n\
             \x20   fn add(&mut self, s: String) {\n        self.items.push(s);\n    }\n\
             \x20   fn count(&self) -> usize {\n        self.items.len()\n    }\n\
             \x20   fn seasoned(&self) -> usize {\n        self.items.len() + self.salt.len()\n    }\n\
             \x20   fn now() -> u64 {\n        0\n    }\n\
             \x20   fn hash(input: &str) -> u64 {\n        7\n    }\n}\n",
            4,
            2,
        );
        assert!(
            findings.is_empty(),
            "pure helpers counted as responsibilities: {findings:?}"
        );
    }

    #[test]
    fn genuinely_disjoint_inherent_methods_are_still_flagged() {
        // The guard on the two exemptions above: a type whose *own*
        // inherent methods split cleanly into two field-disjoint halves is
        // exactly what this rule exists to find, and must still fire.
        let findings = check_rust(
            "struct Mixed {\n    a: i32,\n    b: i32,\n}\n\
             impl Mixed {\n\
             \x20   fn inc_a(&mut self) {\n        self.a += 1;\n    }\n\
             \x20   fn read_a(&self) -> i32 {\n        self.a\n    }\n\
             \x20   fn inc_b(&mut self) {\n        self.b += 1;\n    }\n\
             \x20   fn read_b(&self) -> i32 {\n        self.b\n    }\n}\n",
            4,
            2,
        );
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("2 disconnected"));
    }

    #[test]
    fn a_test_double_in_a_cfg_test_module_is_exempt() {
        let findings = check_rust(
            "#[cfg(test)]\nmod tests {\n\
             \x20   struct Fake {\n        a: i32,\n        b: i32,\n    }\n\
             \x20   impl Fake {\n\
             \x20       fn inc_a(&mut self) {\n            self.a += 1;\n        }\n\
             \x20       fn read_a(&self) -> i32 {\n            self.a\n        }\n\
             \x20       fn inc_b(&mut self) {\n            self.b += 1;\n        }\n\
             \x20       fn read_b(&self) -> i32 {\n            self.b\n        }\n    }\n}\n",
            4,
            2,
        );
        assert!(
            findings.is_empty(),
            "test double reported as a design smell: {findings:?}"
        );
    }

    #[test]
    fn rust_struct_field_clusters_across_impl_methods() {
        let code = "struct Mixed {\n    a: i32,\n    b: i32,\n}\nimpl Mixed {\n    fn inc_a(&mut self) {\n        self.a += 1;\n    }\n    fn read_a(&self) -> i32 {\n        self.a\n    }\n    fn inc_b(&mut self) {\n        self.b += 1;\n    }\n    fn read_b(&self) -> i32 {\n        self.b\n    }\n}\n";
        let file = SourceFile::new("t.rs", code, LanguageIdentifier::rust()).unwrap();
        let ast = vord_parser_rust::RustParser::new().parse(&file).unwrap();
        let files = vec![(file, ast)];
        let findings: Vec<Finding> = LowCohesionRule::new(4, 2)
            .check(&files)
            .into_iter()
            .map(|(_, f)| f)
            .collect();
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("Mixed"));
    }
}
