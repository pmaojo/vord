//! Rule: a domain method whose signature is a row of bare primitives —
//! **primitive obsession**. `new Order(id: string, customerId: string, currency:
//! string, amount: number)` compiles happily when the caller swaps the two ids,
//! or passes cents where units were meant, because the type system has been told
//! nothing about what those values *are*. Value objects (`OrderId`,
//! `CustomerId`, `Money`) move that check from code review to the compiler and
//! give the invariant one place to live.
//!
//! Counts only parameters whose declared type is data
//! (`yunq_symbols::is_primitive_type`, which sees through `Vec<String>` and
//! `Optional[int]`), so a constructor taking four injected collaborators is
//! `smells:constructor-over-injection`'s finding, not this one. Unannotated
//! parameters are not counted at all — with no declared type there is no
//! evidence either way, and guessing would flag every untyped Python signature.
//!
//! Related but distinct from a plain parameter count (SonarQube S107, CodeQL's
//! `FunctionsWithManyParameters.ql`): four strings in a domain constructor are a
//! modeling gap even though four parameters are unremarkable anywhere else,
//! which is why this rule is scoped to the domain layer and typed.

use std::collections::BTreeSet;

use yunq_ast::{AstNode, NodeKind, SourceFile};
use yunq_rules_engine::{CrossFileRule, Finding, IssueType, RuleId, RuleMetadata, Severity};
use yunq_symbols::{function_params, is_primitive_type, ClassRegistry, MemberInfo, MethodInfo};

use crate::common::{is_constructor, is_domain_path, is_value_object, wire_dto_names};

/// Every named function-like node in a file, with the name it is known by.
///
/// Two shapes, because half the TypeScript in the world declares functions the
/// second way: a `FunctionDef` that carries its own name (`function place(..)`,
/// `def place(..)`, `func Place(..)`), and a `VariableDecl` whose initializer is
/// a function (`export const place = (..) => ..`) — where the name lives on the
/// declaration, not on the function. Keyed by span so a node reachable both ways
/// is reported once.
fn named_functions(ast: &AstNode) -> Vec<(&str, &AstNode)> {
    let mut found: Vec<(&str, &AstNode)> = Vec::new();
    let mut seen: BTreeSet<(u32, u32)> = BTreeSet::new();
    for node in ast.descendants() {
        let named = if *node.kind() == NodeKind::VariableDecl {
            let name = node.children().iter().find(|c| *c.kind() == NodeKind::Identifier);
            let function = node.children().iter().find(|c| *c.kind() == NodeKind::FunctionDef);
            name.zip(function)
        } else if *node.kind() == NodeKind::FunctionDef {
            node.children().iter().find(|c| *c.kind() == NodeKind::Identifier).map(|name| (name, node))
        } else {
            None
        };
        let Some((name, function)) = named else { continue };
        let span = function.span();
        if seen.insert((span.start_line, span.start_col)) {
            found.push((name.text(), function));
        }
    }
    found
}

fn primitive_members(params: &[MemberInfo]) -> Vec<String> {
    params
        .iter()
        .filter_map(|param| {
            let declared = param.declared_type.as_deref()?;
            is_primitive_type(declared).then(|| format!("{}: {declared}", param.name))
        })
        .collect()
}

fn primitive_params(method: &MethodInfo<'_>) -> Vec<String> {
    primitive_members(&method.params)
}

pub struct PrimitiveObsessionRule {
    id: RuleId,
    max_primitives: usize,
}

impl PrimitiveObsessionRule {
    pub fn new(max_primitives: usize) -> Self {
        Self { id: RuleId::new("ddd:primitive-obsession").expect("valid rule id"), max_primitives }
    }
}

impl Default for PrimitiveObsessionRule {
    /// Three primitives is a coordinate or a range; four is a signature nobody
    /// can call correctly without reading its implementation.
    fn default() -> Self {
        Self::new(3)
    }
}

impl CrossFileRule for PrimitiveObsessionRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn default_severity(&self) -> Severity {
        Severity::Minor
    }

    fn remediation_effort_minutes(&self) -> u32 {
        60
    }

    fn issue_type(&self) -> IssueType {
        IssueType::CodeSmell
    }

    fn metadata(&self) -> RuleMetadata {
        RuleMetadata {
            description: "A domain method takes several bare primitives, so nothing stops a caller from swapping or mis-scaling them. Introduce value objects that carry the meaning and the invariant.".into(),
            tags: vec!["ddd".into(), "value-object".into(), "domain-model".into(), "cross-file".into()],
            cwe: None,
            produces_hotspots: false,
        }
    }

    fn check(&self, files: &[(SourceFile, AstNode)]) -> Vec<(usize, Finding)> {
        let views: Vec<(&str, &AstNode)> = files
            .iter()
            .filter(|(file, _)| is_domain_path(file.path()))
            .filter(|(file, _)| !yunq_rules_engine::is_test_only_path(file.path()))
            .map(|(file, ast)| (file.path(), ast))
            .collect();
        if views.is_empty() {
            return Vec::new();
        }
        let registry = ClassRegistry::build_cross_file(&views);
        let dtos: std::collections::BTreeSet<String> =
            views.iter().flat_map(|(_, ast)| wire_dto_names(ast)).collect();
        let mut findings = Vec::new();
        for class in registry.iter() {
            if dtos.contains(&class.name) {
                continue;
            }
            let Some(index) = files.iter().position(|(file, _)| file.path() == class.file) else { continue };
            let value_object = is_value_object(class);
            for method in &class.methods {
                if value_object && is_constructor(method, class) {
                    continue;
                }
                let primitives = primitive_params(method);
                if primitives.len() <= self.max_primitives {
                    continue;
                }
                findings.push((
                    index,
                    Finding::new(
                        format!(
                            "`{}::{}` takes {} bare primitive parameters ({}) — a caller that swaps two of them still compiles; wrap them in value objects that carry their meaning and their invariant",
                            class.name,
                            method.name,
                            primitives.len(),
                            primitives.join(", ")
                        ),
                        method.span,
                    ),
                ));
            }
        }
        findings.extend(self.free_function_findings(files, &views));
        findings
    }
}

impl PrimitiveObsessionRule {
    /// The same defect in code that has no classes at all.
    ///
    /// A functional TypeScript module (`export const placeOrder = (id: string,
    /// customerId: string, ...) => ..`), a Go package of plain functions, a
    /// Python module of `def`s: none of them reach `ClassRegistry`, and all of
    /// them can lose a customer's order to two transposed strings. Methods are
    /// already covered above, so a function that belongs to a type is skipped
    /// here to avoid reporting it twice.
    fn free_function_findings(
        &self,
        files: &[(SourceFile, AstNode)],
        views: &[(&str, &AstNode)],
    ) -> Vec<(usize, Finding)> {
        let mut findings = Vec::new();
        for (path, ast) in views {
            let Some(index) = files.iter().position(|(file, _)| file.path() == *path) else { continue };
            let methods: BTreeSet<(u32, u32)> = ClassRegistry::build(ast)
                .iter()
                .flat_map(|class| class.methods.iter().map(|m| (m.span.start_line, m.span.start_col)))
                .collect();
            for (name, function) in named_functions(ast) {
                let span = function.span();
                if methods.contains(&(span.start_line, span.start_col)) {
                    continue;
                }
                let primitives = primitive_members(&function_params(function));
                if primitives.len() <= self.max_primitives {
                    continue;
                }
                findings.push((
                    index,
                    Finding::new(
                        format!(
                            "`{name}` takes {} bare primitive parameters ({}) — a caller that swaps two of them still compiles; wrap them in value objects that carry their meaning and their invariant",
                            primitives.len(),
                            primitives.join(", ")
                        ),
                        span,
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

    fn check(path: &str, code: &str, language: LanguageIdentifier) -> Vec<Finding> {
        let file = SourceFile::new(path, code, language.clone()).unwrap();
        let ast = if language == LanguageIdentifier::typescript() {
            yunq_parser_typescript::TypeScriptParser::new().parse(&file).unwrap()
        } else if language == LanguageIdentifier::python() {
            yunq_parser_python::PythonParser::new().parse(&file).unwrap()
        } else {
            yunq_parser_rust::RustParser::new().parse(&file).unwrap()
        };
        PrimitiveObsessionRule::default().check(&[(file, ast)]).into_iter().map(|(_, f)| f).collect()
    }

    #[test]
    fn flags_a_constructor_of_four_interchangeable_strings() {
        let code = "export class Order {\n  constructor(id: string, customerId: string, currency: string, note: string) {}\n}\n";
        let findings = check("src/domain/order.ts", code, LanguageIdentifier::typescript());
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("4 bare primitive parameters"), "{}", findings[0].message);
        assert!(findings[0].message.contains("customerId: string"));
    }

    #[test]
    fn allows_three_primitives() {
        let code = "export class Point {\n  constructor(x: number, y: number, z: number) {}\n}\n";
        assert!(check("src/domain/point.ts", code, LanguageIdentifier::typescript()).is_empty());
    }

    #[test]
    fn value_object_parameters_are_not_primitives() {
        let code = "export class Order {\n  constructor(id: OrderId, customer: CustomerId, total: Money, note: Note) {}\n}\n";
        assert!(check("src/domain/order.ts", code, LanguageIdentifier::typescript()).is_empty());
    }

    #[test]
    fn a_value_objects_own_constructor_is_where_primitives_become_a_type() {
        let code = "pub struct Span {\n    start_line: u32,\n    start_col: u32,\n    end_line: u32,\n    end_col: u32,\n}\n\nimpl Span {\n    pub fn new(start_line: u32, start_col: u32, end_line: u32, end_col: u32) -> Self {\n        Self { start_line, start_col, end_line, end_col }\n    }\n}\n";
        assert!(check("src/domain/span.rs", code, LanguageIdentifier::rust()).is_empty());
    }

    #[test]
    fn an_entity_constructor_with_identity_to_protect_is_still_flagged() {
        let code = "export class Order {\n  private id: string = '';\n  private status: string = '';\n  constructor(id: string, customerId: string, currency: string, note: string) {}\n}\n";
        let findings = check("src/domain/order.ts", code, LanguageIdentifier::typescript());
        assert_eq!(findings.len(), 1, "{findings:?}");
    }

    #[test]
    fn a_value_objects_other_methods_are_still_judged() {
        let code = "pub struct Money {\n    amount: i64,\n}\n\nimpl Money {\n    pub fn rescale(&self, scale: u8, mode: String, precision: u8, locale: String) -> Self {\n        self.clone()\n    }\n}\n";
        let findings = check("src/domain/money.rs", code, LanguageIdentifier::rust());
        assert_eq!(findings.len(), 1, "{findings:?}");
    }

    #[test]
    fn injected_collaborators_are_not_this_rules_business() {
        let code = "export class OrderPolicy {\n  constructor(a: Repo, b: Clock, c: Rates, d: Bus) {}\n}\n";
        assert!(check("src/domain/order_policy.ts", code, LanguageIdentifier::typescript()).is_empty());
    }

    #[test]
    fn flags_a_functional_typescript_factory_with_no_class_in_sight() {
        // `export const` / arrow-function code never reaches `ClassRegistry`;
        // the modeling gap is identical, so the rule looks at free functions too.
        let code = "export const placeOrder = (id: string, customerId: string, currency: string, note: string) => {\n  return { id, customerId, currency, note };\n};\n";
        let findings = check("src/domain/place_order.ts", code, LanguageIdentifier::typescript());
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert!(findings[0].message.contains("4 bare primitive parameters"), "{}", findings[0].message);
    }

    #[test]
    fn flags_a_go_package_function() {
        let file = SourceFile::new(
            "internal/domain/order.go",
            "package domain\n\nfunc Place(id string, customer string, currency string, note string) error {\n\treturn nil\n}\n",
            LanguageIdentifier::go(),
        )
        .unwrap();
        let ast = yunq_parser_go::GoParser::new().parse(&file).unwrap();
        let findings: Vec<Finding> =
            PrimitiveObsessionRule::default().check(&[(file, ast)]).into_iter().map(|(_, f)| f).collect();
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert!(findings[0].message.contains("`Place`"));
    }

    #[test]
    fn a_method_is_not_reported_twice_as_a_free_function() {
        let code = "export class Order {\n  private id: string = '';\n  rename(a: string, b: string, c: string, d: string): void {}\n}\n";
        let findings = check("src/domain/order.ts", code, LanguageIdentifier::typescript());
        assert_eq!(findings.len(), 1, "{findings:?}");
    }

    #[test]
    fn silent_outside_the_domain_layer() {
        let code = "export class OrderRequest {\n  constructor(id: string, customerId: string, currency: string, note: string) {}\n}\n";
        assert!(check("src/adapters/http/order_request.ts", code, LanguageIdentifier::typescript()).is_empty());
    }

    #[test]
    fn flags_a_rust_constructor_of_primitives() {
        let code = "pub struct Order;\n\nimpl Order {\n    pub fn new(id: String, customer: String, cents: i64, currency: String) -> Self {\n        Self\n    }\n}\n";
        let findings = check("src/domain/order.rs", code, LanguageIdentifier::rust());
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("4 bare primitive parameters"));
    }

    #[test]
    fn flags_an_annotated_python_method() {
        let code = "class Order:\n    def rename(self, first: str, last: str, nickname: str, note: str) -> None:\n        pass\n";
        let findings = check("src/domain/order.py", code, LanguageIdentifier::python());
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("`Order::rename`"));
    }

    #[test]
    fn unannotated_parameters_are_never_counted() {
        let code = "class Order:\n    def rename(self, first, last, nickname, note):\n        pass\n";
        assert!(check("src/domain/order.py", code, LanguageIdentifier::python()).is_empty());
    }

    #[test]
    fn threshold_is_configurable() {
        let file = SourceFile::new(
            "src/domain/point.ts",
            "export class Point {\n  constructor(x: number, y: number) {}\n}\n",
            LanguageIdentifier::typescript(),
        )
        .unwrap();
        let ast = yunq_parser_typescript::TypeScriptParser::new().parse(&file).unwrap();
        let files = vec![(file, ast)];
        assert_eq!(PrimitiveObsessionRule::new(1).check(&files).len(), 1);
        assert!(PrimitiveObsessionRule::new(2).check(&files).is_empty());
    }
}
