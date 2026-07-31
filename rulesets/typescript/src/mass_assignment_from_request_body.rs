//! Rule: flags `Object.assign(target, req.body)` and object-spread
//! `{ ...req.body }` — merging a raw request body into an object with no
//! allowlist lets the caller set *any* property the object happens to
//! have, including ones the code never meant to expose (mass assignment),
//! and on plain objects can set `__proto__`/`constructor.prototype` keys
//! that pollute every object's prototype (prototype pollution).

use yunq_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use yunq_rules_engine::{Finding, IssueType, Rule, RuleId, RuleMetadata, Severity};

use crate::common::{call_arguments, is_other};

/// Matches the same request-object marker convention `owasp:xss`/
/// `owasp:injection`'s taint configs use for their source markers, kept
/// consistent here even though this rule matches text directly rather than
/// tracing a taint flow.
const EXTERNAL_INPUT_MARKERS: &[&str] = &["req.body", "req.query", "req.params"];

fn contains_external_input(node: &AstNode) -> bool {
    EXTERNAL_INPUT_MARKERS
        .iter()
        .any(|marker| node.subtree_contains_text(marker))
}

fn flagged_object_assign(node: &AstNode) -> Option<&AstNode> {
    if *node.kind() != NodeKind::Call {
        return None;
    }
    let callee = node.first_child()?;
    if callee.text() != "Object.assign" {
        return None;
    }
    let args = call_arguments(node);
    // The first argument is the mutated target; only later arguments are
    // merged in, so only those count as the unvalidated-source risk.
    args.get(1..)?
        .iter()
        .find(|arg| contains_external_input(arg))
        .map(|_| node)
}

fn flagged_spreads(ast: &AstNode) -> impl Iterator<Item = &AstNode> {
    ast.descendants()
        .filter(|n| is_other(n, "object"))
        .flat_map(|obj| {
            obj.children()
                .iter()
                .filter(|c| is_other(c, "spread_element"))
        })
        .filter(|spread| spread.first_child().is_some_and(contains_external_input))
}

pub struct MassAssignmentFromRequestBodyRule {
    id: RuleId,
}

impl MassAssignmentFromRequestBodyRule {
    pub fn new() -> Self {
        Self {
            id: RuleId::new("typescript:mass-assignment-from-request-body").expect("valid rule id"),
        }
    }
}

impl Default for MassAssignmentFromRequestBodyRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for MassAssignmentFromRequestBodyRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn applies_to(&self, lang: &LanguageIdentifier) -> bool {
        *lang == LanguageIdentifier::typescript()
    }

    fn default_severity(&self) -> Severity {
        Severity::Critical
    }

    fn issue_type(&self) -> IssueType {
        IssueType::Vulnerability
    }

    fn metadata(&self) -> RuleMetadata {
        RuleMetadata {
            description: "Merging a request body into an object with no allowlist (Object.assign or object spread) lets the caller set any property, including __proto__/constructor.prototype — mass assignment and prototype pollution.".into(),
            tags: vec!["typescript".into(), "security".into(), "owasp-a08".into()],
            cwe: Some(915),
            produces_hotspots: false,
        }
    }

    fn check(&self, _file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        let assigns = ast.descendants().filter_map(flagged_object_assign).map(|n| {
            Finding::new("Object.assign merges a request body with no allowlist — mass assignment / prototype pollution risk", n.span())
        });
        let spreads = flagged_spreads(ast).map(|n| {
            Finding::new("spreading a request body into an object with no allowlist is a mass assignment / prototype pollution risk", n.span())
        });
        assigns.chain(spreads).collect()
    }
}

#[cfg(test)]
mod tests {
    use yunq_ast::SourceFile;
    use yunq_rules_engine::AstParser;

    use super::*;

    fn check(code: &str) -> Vec<Finding> {
        let file = SourceFile::new("t.ts", code, LanguageIdentifier::typescript()).unwrap();
        let ast = yunq_parser_typescript::TypeScriptParser::new()
            .parse(&file)
            .unwrap();
        MassAssignmentFromRequestBodyRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_object_assign_with_request_body() {
        assert_eq!(check("Object.assign(user, req.body);\n").len(), 1);
    }

    #[test]
    fn flags_object_spread_of_request_body() {
        assert_eq!(check("const merged = { ...req.body };\n").len(), 1);
    }

    #[test]
    fn flags_request_query_and_params_too() {
        assert_eq!(check("Object.assign(user, req.query);\n").len(), 1);
        assert_eq!(check("Object.assign(user, req.params);\n").len(), 1);
    }

    #[test]
    fn allows_spread_of_unrelated_object() {
        assert!(check("const safe = { ...defaults };\n").is_empty());
    }

    #[test]
    fn allows_object_assign_of_unrelated_source() {
        assert!(check("Object.assign(user, defaults);\n").is_empty());
    }

    #[test]
    fn allows_object_assign_when_body_is_the_target() {
        assert!(check("Object.assign(req.body, defaults);\n").is_empty());
    }
}
