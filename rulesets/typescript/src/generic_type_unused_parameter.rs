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
    // Everything else this declaration's own text says, once its own
    // `<...>` parameter list is removed — the one place each name is
    // guaranteed to appear without "using" it.
    let rest = decl.text().replacen(type_params.text(), "", 1);
    type_params
        .children()
        .iter()
        .filter(|p| is_other(p, "type_parameter"))
        .filter(|p| !contains_word(&rest, type_parameter_name(p)))
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
}
