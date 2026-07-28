//! Rule: Single Responsibility via LCOM (Lack of Cohesion of Methods) — a
//! class whose methods split into more than one connected component when
//! grouped by "touches the same field" bundles more than one responsibility,
//! even when `smells:god-class`'s raw method/field counts stay under
//! threshold (a class can have a modest method count and still be two
//! unrelated classes glued together). Reuses `yunq_symbols::ClassRegistry`
//! for extraction — same wiring as `smells:god-class`/`smells:feature-envy`.

use std::collections::{BTreeMap, BTreeSet};

use yunq_ast::{AstNode, NodeKind, SourceFile};
use yunq_rules_engine::{CrossFileRule, Finding, IssueType, RuleId, RuleMetadata, Severity};
use yunq_symbols::{ClassInfo, ClassRegistry, MethodInfo};

/// Constructors are excluded from the cohesion graph: their whole job is
/// initializing every field at once, so including them would trivially
/// connect every method through the constructor and mask exactly the
/// disconnected-responsibilities problem this rule looks for.
const CONSTRUCTOR_NAMES: &[&str] = &["constructor", "__init__"];

fn non_constructor_methods<'a, 'b>(class: &'b ClassInfo<'a>) -> Vec<&'b MethodInfo<'a>> {
    class.methods.iter().filter(|m| !CONSTRUCTOR_NAMES.contains(&m.name.as_str())).collect()
}

/// The subset of `field_names` that `method_body` reads or writes via a bare
/// `self.field`/`this.field` access.
fn own_field_accesses<'a>(method_body: &AstNode, field_names: &BTreeSet<&'a str>) -> BTreeSet<&'a str> {
    let mut used = BTreeSet::new();
    for access in method_body.descendants().filter(|n| *n.kind() == NodeKind::MemberAccess) {
        let Some(base) = access.first_child() else { continue };
        if base.text() != "self" && base.text() != "this" {
            continue;
        }
        let Some(prop) = access.children().get(1) else { continue };
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
        Self { parent: (0..n).collect() }
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

/// Groups `class`'s methods into connected components — two methods land in
/// the same group iff there is a chain of methods between them, each pair
/// sharing at least one own-field access. More than one group means the
/// class's methods don't actually cohere around one set of state.
fn method_clusters(class: &ClassInfo<'_>) -> Vec<Vec<String>> {
    let field_names: BTreeSet<&str> = class.fields.iter().map(|f| f.name.as_str()).collect();
    let methods = non_constructor_methods(class);
    let accesses: Vec<BTreeSet<&str>> = methods.iter().map(|m| own_field_accesses(m.node, &field_names)).collect();
    let mut uf = UnionFind::new(methods.len());
    for i in 0..accesses.len() {
        for j in (i + 1)..accesses.len() {
            if !accesses[i].is_disjoint(&accesses[j]) {
                uf.union(i, j);
            }
        }
    }
    let mut groups: BTreeMap<usize, Vec<String>> = BTreeMap::new();
    for (i, method) in methods.iter().enumerate() {
        groups.entry(uf.find(i)).or_default().push(method.name.clone());
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
        Self { id: RuleId::new("smells:low-cohesion").expect("valid rule id"), min_methods, min_fields }
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
        let views: Vec<(&str, &AstNode)> = files.iter().map(|(file, ast)| (file.path(), ast)).collect();
        let registry = ClassRegistry::build_cross_file(&views);
        registry
            .iter()
            .filter_map(|class| {
                if non_constructor_methods(class).len() < self.min_methods || class.fields.len() < self.min_fields {
                    return None;
                }
                let clusters = method_clusters(class);
                if clusters.len() < 2 {
                    return None;
                }
                let span = class.span?;
                let index = files.iter().position(|(file, _)| file.path() == class.file)?;
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
    use yunq_ast::LanguageIdentifier;
    use yunq_rules_engine::AstParser;

    fn check_ts(code: &str, min_methods: usize, min_fields: usize) -> Vec<Finding> {
        let file = SourceFile::new("t.ts", code, LanguageIdentifier::typescript()).unwrap();
        let ast = yunq_parser_typescript::TypeScriptParser::new().parse(&file).unwrap();
        let files = vec![(file, ast)];
        LowCohesionRule::new(min_methods, min_fields).check(&files).into_iter().map(|(_, f)| f).collect()
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
        let ast = yunq_parser_python::PythonParser::new().parse(&file).unwrap();
        let files = vec![(file, ast)];
        let findings: Vec<Finding> =
            LowCohesionRule::new(4, 2).check(&files).into_iter().map(|(_, f)| f).collect();
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("Mixed"));
    }

    #[test]
    fn rust_struct_field_clusters_across_impl_methods() {
        let code = "struct Mixed {\n    a: i32,\n    b: i32,\n}\nimpl Mixed {\n    fn inc_a(&mut self) {\n        self.a += 1;\n    }\n    fn read_a(&self) -> i32 {\n        self.a\n    }\n    fn inc_b(&mut self) {\n        self.b += 1;\n    }\n    fn read_b(&self) -> i32 {\n        self.b\n    }\n}\n";
        let file = SourceFile::new("t.rs", code, LanguageIdentifier::rust()).unwrap();
        let ast = yunq_parser_rust::RustParser::new().parse(&file).unwrap();
        let files = vec![(file, ast)];
        let findings: Vec<Finding> =
            LowCohesionRule::new(4, 2).check(&files).into_iter().map(|(_, f)| f).collect();
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("Mixed"));
    }
}
