//! Rule: flags an arrow function assigned to an exported `const` with no
//! parameter types and no return type annotation. Its parameters are
//! implicitly `any`, and without a return type the compiler infers
//! whatever the (already-untyped) body happens to produce — so a caller in
//! another file sees an exported function with essentially no type
//! contract at all. Narrowed to exported, fully-untyped arrow functions,
//! since that's the syntactic case this analyzer can actually confirm
//! without inferring what the body's real return shape is.

use vord_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use vord_rules_engine::{Finding, IssueType, Rule, RuleId, RuleMetadata, Severity};

use crate::common::is_other;

/// `NodeKind::FunctionDef` collapses arrow functions together with
/// `function` declarations/expressions, so an arrow function is
/// recognized here by what it *doesn't* start with — the `function`
/// keyword — rather than by kind name.
fn is_arrow_function(func: &AstNode) -> bool {
    let text = func.text().trim_start();
    let text = text.strip_prefix("async").map(str::trim_start).unwrap_or(text);
    !text.starts_with("function")
}

fn is_untyped_arrow(func: &AstNode) -> bool {
    if *func.kind() != NodeKind::FunctionDef || !is_arrow_function(func) {
        return false;
    }
    if func.text().contains("):") {
        return false;
    }
    let params_untyped = func
        .children()
        .iter()
        .find(|c| is_other(c, "formal_parameters"))
        .is_none_or(|params| {
            params.children().iter().all(|p| {
                (is_other(p, "required_parameter") || is_other(p, "optional_parameter"))
                    && !p.children().iter().any(|c| is_other(c, "type_annotation"))
            })
        });
    params_untyped
}

fn flagged_export(node: &AstNode) -> Vec<&AstNode> {
    if !is_other(node, "export_statement") {
        return Vec::new();
    }
    node.descendants()
        .filter(|n| *n.kind() == NodeKind::VariableDecl)
        .filter_map(|decl| decl.children().get(1))
        .filter(|value| is_untyped_arrow(value))
        .collect()
}

pub struct ImplicitAnyReturnInArrowFunctionRule {
    id: RuleId,
}

impl ImplicitAnyReturnInArrowFunctionRule {
    pub fn new() -> Self {
        Self {
            id: RuleId::new("typescript:implicit-any-return-in-arrow-function")
                .expect("valid rule id"),
        }
    }
}

impl Default for ImplicitAnyReturnInArrowFunctionRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for ImplicitAnyReturnInArrowFunctionRule {
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
            description: "This exported arrow function has no parameter types and no return type, so it exposes essentially no type contract to callers in other files. Annotate its parameters and return type.".into(),
            tags: vec!["typescript".into(), "type-safety".into()],
            cwe: Some(704),
            produces_hotspots: false,
        }
    }

    fn check(&self, _file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        ast.descendants()
            .flat_map(flagged_export)
            .map(|n| {
                Finding::new(
                    "this exported arrow function has no parameter types or return type; callers in other files see no type contract",
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
        ImplicitAnyReturnInArrowFunctionRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_exported_fully_untyped_arrow_function() {
        assert_eq!(check("export const f = (x) => x + 1;\n").len(), 1);
    }

    #[test]
    fn allows_exported_arrow_with_return_type() {
        assert!(check("export const f = (x): number => x + 1;\n").is_empty());
    }

    #[test]
    fn allows_exported_arrow_with_param_type() {
        assert!(check("export const f = (x: number) => x + 1;\n").is_empty());
    }

    #[test]
    fn allows_non_exported_untyped_arrow() {
        assert!(check("const f = (x) => x + 1;\n").is_empty());
    }

    #[test]
    fn allows_exported_function_declaration() {
        assert!(check("export function f(x) { return x + 1; }\n").is_empty());
    }
}
