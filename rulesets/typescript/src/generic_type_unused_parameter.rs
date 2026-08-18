//! Rule: flags a generic type parameter (`<T>`) declared on a function,
//! interface, type alias, or class that is never referenced anywhere else
//! in that declaration. An unused type parameter buys nothing — it doesn't
//! constrain or connect any part of the signature — and usually means
//! either a leftover from a refactor or a spot that should have used the
//! parameter but didn't.

use vord_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use vord_rules_engine::{Finding, IssueType, Rule, RuleId, RuleMetadata, Severity};

use crate::common::{contains_word, is_other};

const DECLARATION_KINDS: [&str; 3] = [
    "interface_declaration",
    "type_alias_declaration",
    "class_declaration",
];

fn is_generic_declaration(node: &AstNode) -> bool {
    *node.kind() == NodeKind::FunctionDef
        || DECLARATION_KINDS.iter().any(|k| is_other(node, k))
}

fn type_parameter_name(param: &AstNode) -> &str {
    param.first_child().map(|n| n.text()).unwrap_or(param.text())
}

fn unused_type_params(decl: &AstNode) -> Vec<&AstNode> {
    let Some(type_params) = decl.children().iter().find(|c| is_other(c, "type_parameters"))
    else {
        return Vec::new();
    };
    // For each parameter, remove only *that parameter's own* text from the
    // declaration before checking for other occurrences of its name —
    // never the whole `<...>` list. A sibling type parameter's constraint
    // or default (`K = T`, `K extends T`) is a real use of `T` and must
    // stay visible in the "rest" text; stripping the entire parameter
    // list would erase that use and misreport `T` as unused.
    type_params
        .children()
        .iter()
        .filter(|p| is_other(p, "type_parameter"))
        .filter(|p| {
            let rest = decl.text().replacen(p.text(), "", 1);
            !contains_word(&rest, type_parameter_name(p))
        })
        .collect()
}

pub struct GenericTypeUnusedParameterRule {
    id: RuleId,
}

impl GenericTypeUnusedParameterRule {
    pub fn new() -> Self {
        Self {
            id: RuleId::new("typescript:generic-type-unused-parameter").expect("valid rule id"),
        }
    }
}

impl Default for GenericTypeUnusedParameterRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for GenericTypeUnusedParameterRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn applies_to(&self, lang: &LanguageIdentifier) -> bool {
        *lang == LanguageIdentifier::typescript()
    }

    fn default_severity(&self) -> Severity {
        Severity::Minor
    }

    fn issue_type(&self) -> IssueType {
        IssueType::CodeSmell
    }

    fn remediation_effort_minutes(&self) -> u32 {
        5
    }

    fn metadata(&self) -> RuleMetadata {
        RuleMetadata {
            description: "This generic type parameter is never referenced anywhere in its own declaration, so it constrains nothing. Remove it, or use it where it was meant to appear.".into(),
            tags: vec!["typescript".into(), "clarity".into()],
            cwe: None,
            produces_hotspots: false,
        }
    }

    fn check(&self, _file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        ast.descendants()
            .filter(|n| is_generic_declaration(n))
            .flat_map(unused_type_params)
            .map(|n| {
                Finding::new(
                    format!("type parameter `{}` is never used in this declaration", n.text()),
                    n.span(),
                )
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use vord_ast::SourceFile;
    use vord_rules_engine::AstParser;

    use super::*;

    fn check(code: &str) -> Vec<Finding> {
        let file = SourceFile::new("t.ts", code, LanguageIdentifier::typescript()).unwrap();
        let ast = vord_parser_typescript::TypeScriptParser::new()
            .parse(&file)
            .unwrap();
        GenericTypeUnusedParameterRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_unused_function_type_parameter() {
        let findings = check("function f<T>(x: number): number { return x; }\n");
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn allows_type_parameter_used_in_params() {
        assert!(check("function f<T>(x: T): T { return x; }\n").is_empty());
    }

    #[test]
    fn flags_unused_interface_type_parameter() {
        let findings = check("interface Box<T> {\n  value: number;\n}\n");
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn allows_type_parameter_used_in_interface_body() {
        assert!(check("interface Box<T> {\n  value: T;\n}\n").is_empty());
    }

    #[test]
    fn allows_type_parameter_used_in_extends_clause() {
        assert!(check("interface Box<T> extends Base<T> {\n  value: number;\n}\n").is_empty());
    }

    #[test]
    fn allows_declaration_with_no_type_parameters() {
        assert!(check("function f(x: number): number { return x; }\n").is_empty());
    }

    /// Regression: a type parameter used only as another type parameter's
    /// default (`K = T`) is a real use of `T`, not an unused parameter.
    /// Stripping the whole `<...>` list before searching for uses used to
    /// erase this and misreport `T` as unused.
    #[test]
    fn allows_type_parameter_used_as_sibling_default() {
        let code = "class Container<T, K = T> {\n  value!: K;\n}\n";
        assert!(check(code).is_empty());
    }

    /// Same false positive via an `extends` constraint referencing a
    /// sibling parameter instead of a default value.
    #[test]
    fn allows_type_parameter_used_in_sibling_constraint() {
        let code = "interface Pair<A, B extends A> {\n  first: A;\n  second: B;\n}\n";
        assert!(check(code).is_empty());
    }
}
