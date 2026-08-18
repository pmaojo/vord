//! Rule: flags a class method that reads `this` in its own body being
//! passed elsewhere as a bare callback (`this.method` handed to a call as
//! an argument, with no `.bind(this)` and not itself wrapped in an arrow
//! function). A regular method's `this` is whatever the *call site* sets it
//! to — passed bare to `setTimeout`, an event target, or another callback
//! consumer, it typically runs with `this` as `undefined` or the wrong
//! object, so any `this.foo` inside silently breaks at call time instead of
//! at compile time.

use std::collections::HashSet;

use vord_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use vord_rules_engine::{Finding, IssueType, Rule, RuleId, RuleMetadata, Severity};

use crate::common::{call_arguments, is_other};

/// Names of non-static, non-arrow class methods whose own body reads
/// `this`. `NodeKind::FunctionDef` collapses `method_definition` together
/// with function declarations and arrow functions, so class methods are
/// found structurally instead — as the direct `FunctionDef` children of a
/// `class_body`, which is where the grammar puts them and nothing else.
fn this_using_method_names(ast: &AstNode) -> HashSet<&str> {
    ast.descendants()
        .filter(|n| is_other(n, "class_body"))
        .flat_map(|body| body.children().iter())
        .filter(|n| *n.kind() == NodeKind::FunctionDef)
        .filter(|n| n.subtree_contains_text("this"))
        .filter_map(|n| n.first_child())
        .filter(|id| *id.kind() == NodeKind::Identifier)
        .map(|id| id.text())
        .filter(|name| !matches!(*name, "constructor"))
        .collect()
}

/// A `this.<name>` member access passed as a bare call argument. A
/// `.bind(this)`-wrapped reference parses as a `Call`, not a
/// `MemberAccess`, so it's already excluded by the `kind()` check below
/// without any special-casing.
fn flagged<'a>(call: &'a AstNode, method_names: &HashSet<&str>) -> Vec<&'a AstNode> {
    call_arguments(call)
        .iter()
        .filter(|arg| {
            *arg.kind() == NodeKind::MemberAccess
                && arg.first_child().is_some_and(|obj| is_other(obj, "this"))
                && arg
                    .children()
                    .last()
                    .is_some_and(|prop| method_names.contains(prop.text()))
        })
        .collect()
}

pub struct UnboundThisInMethodRule {
    id: RuleId,
}

impl UnboundThisInMethodRule {
    pub fn new() -> Self {
        Self {
            id: RuleId::new("typescript:unbound-this-in-method").expect("valid rule id"),
        }
    }
}

impl Default for UnboundThisInMethodRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for UnboundThisInMethodRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn applies_to(&self, lang: &LanguageIdentifier) -> bool {
        *lang == LanguageIdentifier::typescript()
    }

    fn default_severity(&self) -> Severity {
        Severity::Major
    }

    fn issue_type(&self) -> IssueType {
        IssueType::Bug
    }

    fn remediation_effort_minutes(&self) -> u32 {
        5
    }

    fn metadata(&self) -> RuleMetadata {
        RuleMetadata {
            description: "This method uses `this` in its own body but is passed here as a bare callback, with no `.bind(this)` and no arrow wrapper. `this` at the call site typically won't be the instance, so `this.*` inside the method breaks at runtime.".into(),
            tags: vec!["typescript".into(), "reliability".into()],
            cwe: None,
            produces_hotspots: false,
        }
    }

    fn check(&self, _file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        let method_names = this_using_method_names(ast);
        if method_names.is_empty() {
            return Vec::new();
        }
        ast.descendants()
            .filter(|n| *n.kind() == NodeKind::Call)
            .flat_map(|call| flagged(call, &method_names))
            .map(|n| {
                Finding::new(
                    format!(
                        "`this.{}` is passed here as a bare callback but its body uses `this`; bind it (`this.{}.bind(this)`) or wrap it in an arrow function",
                        n.children().last().map(|p| p.text()).unwrap_or_default(),
                        n.children().last().map(|p| p.text()).unwrap_or_default(),
                    ),
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
        UnboundThisInMethodRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_bare_method_reference_passed_as_callback() {
        let code = "class C {\n  method() { this.x = 1; }\n  other() {\n    setTimeout(this.method, 10);\n  }\n}\n";
        assert_eq!(check(code).len(), 1);
    }

    #[test]
    fn allows_bound_method_reference() {
        let code = "class C {\n  method() { this.x = 1; }\n  other() {\n    setTimeout(this.method.bind(this), 10);\n  }\n}\n";
        assert!(check(code).is_empty());
    }

    #[test]
    fn allows_method_call_with_parens() {
        let code = "class C {\n  method() { this.x = 1; }\n  other() {\n    this.method();\n  }\n}\n";
        assert!(check(code).is_empty());
    }

    #[test]
    fn allows_reference_to_method_that_does_not_use_this() {
        let code = "class C {\n  method() { return 1; }\n  other() {\n    setTimeout(this.method, 10);\n  }\n}\n";
        assert!(check(code).is_empty());
    }

    #[test]
    fn allows_arrow_wrapped_reference() {
        let code = "class C {\n  method() { this.x = 1; }\n  other() {\n    setTimeout(() => this.method(), 10);\n  }\n}\n";
        assert!(check(code).is_empty());
    }
}
