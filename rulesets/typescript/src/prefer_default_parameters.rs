//! Rule: flags a function whose first statement reassigns a parameter to
//! `param ?? fallback` or `param || fallback` — the same default belongs in
//! the parameter list (`function f(param = fallback)`), where it's visible
//! at the call site instead of buried in the body.

use vord_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use vord_rules_engine::{Finding, Rule, RuleId, RuleMetadata, Severity};

use crate::common::is_other;

/// Same technique `loose_equality` uses to recover an elided operator token:
/// the gap between `binary_expression`'s two named children.
fn binary_operator(node: &AstNode) -> Option<&'static str> {
    if !is_other(node, "binary_expression") {
        return None;
    }
    let [left, right] = node.children() else {
        return None;
    };
    let node_start = node.byte_range().start;
    let gap_start = left.byte_range().end.saturating_sub(node_start);
    let gap_end = right.byte_range().start.saturating_sub(node_start);
    let between = node.text().get(gap_start..gap_end)?.trim();
    match between {
        "??" => Some("??"),
        "||" => Some("||"),
        _ => None,
    }
}

fn parameter_names(formal_parameters: &AstNode) -> Vec<&str> {
    formal_parameters
        .children()
        .iter()
        .filter_map(|param| {
            if !(is_other(param, "required_parameter") || is_other(param, "optional_parameter")) {
                return None;
            }
            param
                .children()
                .iter()
                .find(|c| *c.kind() == NodeKind::Identifier)
                .map(|id| id.text())
        })
        .collect()
}

fn first_statement_reassigns_param<'a>(body: &'a AstNode, params: &[&str]) -> Option<&'a AstNode> {
    let block = body
        .children()
        .iter()
        .find(|c| is_other(c, "statement_block"))?;
    let first = block.children().first()?;
    if !is_other(first, "expression_statement") {
        return None;
    }
    let [assignment] = first.children() else {
        return None;
    };
    if *assignment.kind() != NodeKind::Assignment {
        return None;
    }
    let [target, value] = assignment.children() else {
        return None;
    };
    if *target.kind() != NodeKind::Identifier || !params.contains(&target.text()) {
        return None;
    }
    binary_operator(value)?;
    let [value_left, _] = value.children() else {
        return None;
    };
    (*value_left.kind() == NodeKind::Identifier && value_left.text() == target.text())
        .then_some(first)
}

fn flagged_function(node: &AstNode) -> Option<&AstNode> {
    if *node.kind() != NodeKind::FunctionDef {
        return None;
    }
    let formal_parameters = node
        .children()
        .iter()
        .find(|c| is_other(c, "formal_parameters"))?;
    let params = parameter_names(formal_parameters);
    if params.is_empty() {
        return None;
    }
    first_statement_reassigns_param(node, &params)
}

pub struct PreferDefaultParametersRule {
    id: RuleId,
}

impl PreferDefaultParametersRule {
    pub fn new() -> Self {
        Self {
            id: RuleId::new("typescript:prefer-default-parameters").expect("valid rule id"),
        }
    }
}

impl Default for PreferDefaultParametersRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for PreferDefaultParametersRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn applies_to(&self, lang: &LanguageIdentifier) -> bool {
        *lang == LanguageIdentifier::typescript()
    }

    fn default_severity(&self) -> Severity {
        Severity::Minor
    }

    fn remediation_effort_minutes(&self) -> u32 {
        2
    }

    fn metadata(&self) -> RuleMetadata {
        RuleMetadata {
            description: "A parameter immediately reassigned to `param ?? fallback`/`param || fallback` should use a default parameter (`function f(param = fallback)`) instead, so the default is visible at the call site.".into(),
            tags: vec!["typescript".into(), "clarity".into()],
            cwe: None,
            produces_hotspots: false,
        }
    }

    fn check(&self, _file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        ast.descendants()
            .filter_map(flagged_function)
            .map(|n| {
                Finding::new(
                    "reassigning a parameter to its own default belongs in the parameter list; use a default parameter instead",
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
        PreferDefaultParametersRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_nullish_reassignment() {
        let findings = check("function f(stationId) { stationId = stationId ?? ''; use(stationId); }\n");
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn flags_or_reassignment() {
        assert_eq!(
            check("function f(name) { name = name || 'anon'; }\n").len(),
            1
        );
    }

    #[test]
    fn allows_default_parameter() {
        assert!(check("function f(stationId = '') { use(stationId); }\n").is_empty());
    }

    #[test]
    fn allows_reassignment_to_different_variable() {
        assert!(check("function f(a) { const b = a ?? ''; }\n").is_empty());
    }

    #[test]
    fn allows_reassignment_not_first_statement() {
        assert!(check("function f(a) { doSomething(); a = a ?? 1; }\n").is_empty());
    }
}
