//! Rule: flags a function parameter typed `unknown` that the body accesses
//! as a member (`param.foo`) with no `typeof`/`instanceof`/`in` narrowing
//! check anywhere in the body first. `unknown` exists specifically to force
//! a narrowing check before use; reading a property straight off it
//! defeats the type checker (accepted only via an implicit widening the
//! author likely didn't intend) and can throw at runtime for values that
//! don't have that shape.

use vord_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use vord_rules_engine::{Finding, IssueType, Rule, RuleId, RuleMetadata, Severity};

use crate::common::is_other;

fn is_unknown_param(param: &AstNode) -> Option<&str> {
    if !(is_other(param, "required_parameter") || is_other(param, "optional_parameter")) {
        return None;
    }
    let name = param.first_child()?;
    if *name.kind() != NodeKind::Identifier {
        return None;
    }
    let annotation = param.children().iter().find(|c| is_other(c, "type_annotation"))?;
    (annotation.text().trim() == ": unknown").then_some(name.text())
}

fn is_narrowed(body: &AstNode) -> bool {
    let text = body.text();
    text.contains("instanceof") || text.contains("typeof") || text.contains(" in ")
}

fn unguarded_access<'a>(body: &'a AstNode, param_name: &str) -> Option<&'a AstNode> {
    if is_narrowed(body) {
        return None;
    }
    body.descendants().find(|n| {
        *n.kind() == NodeKind::MemberAccess
            && n.first_child().is_some_and(|obj| obj.text() == param_name)
    })
}

fn flagged(func: &AstNode) -> Vec<&AstNode> {
    let Some(params) = func.children().iter().find(|c| is_other(c, "formal_parameters")) else {
        return Vec::new();
    };
    let Some(body) = func.children().iter().find(|c| is_other(c, "statement_block")) else {
        return Vec::new();
    };
    params
        .children()
        .iter()
        .filter_map(is_unknown_param)
        .filter_map(|name| unguarded_access(body, name))
        .collect()
}

pub struct UnknownNotNarrowedBeforeUseRule {
    id: RuleId,
}

impl UnknownNotNarrowedBeforeUseRule {
    pub fn new() -> Self {
        Self {
            id: RuleId::new("typescript:unknown-not-narrowed-before-use").expect("valid rule id"),
        }
    }
}

impl Default for UnknownNotNarrowedBeforeUseRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for UnknownNotNarrowedBeforeUseRule {
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
        10
    }

    fn metadata(&self) -> RuleMetadata {
        RuleMetadata {
            description: "This parameter is typed `unknown` but a property is read off it with no `typeof`/`instanceof`/`in` narrowing anywhere in the function body first. `unknown` exists to force a narrowing check before use.".into(),
            tags: vec!["typescript".into(), "type-safety".into()],
            cwe: Some(704),
            produces_hotspots: false,
        }
    }

    fn check(&self, _file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        ast.descendants()
            .filter(|n| *n.kind() == NodeKind::FunctionDef)
            .flat_map(flagged)
            .map(|n| {
                Finding::new(
                    "this reads a property off an `unknown`-typed parameter with no narrowing check first",
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
        UnknownNotNarrowedBeforeUseRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_unguarded_property_access_on_unknown_param() {
        assert_eq!(check("function f(x: unknown) {\n  return x.foo;\n}\n").len(), 1);
    }

    #[test]
    fn allows_access_after_typeof_narrowing() {
        let code = "function f(x: unknown) {\n  if (typeof x === 'object' && x !== null) {\n    return (x as { foo: unknown }).foo;\n  }\n  return undefined;\n}\n";
        assert!(check(code).is_empty());
    }

    #[test]
    fn allows_access_after_instanceof_narrowing() {
        let code = "function f(x: unknown) {\n  if (x instanceof Foo) {\n    return x.foo;\n  }\n  return undefined;\n}\n";
        assert!(check(code).is_empty());
    }

    #[test]
    fn allows_untyped_parameter() {
        assert!(check("function f(x) {\n  return x.foo;\n}\n").is_empty());
    }

    #[test]
    fn allows_typed_non_unknown_parameter() {
        assert!(check("function f(x: MyType) {\n  return x.foo;\n}\n").is_empty());
    }
}
