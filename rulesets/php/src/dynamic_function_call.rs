use yunq_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use yunq_rules_engine::{Finding, IssueType, Rule, RuleId, Severity};

use crate::common::{SUPERGLOBALS, callee_node, is_other};

const DYNAMIC_CALL_FUNCTIONS: &[&str] = &[
    "call_user_func",
    "call_user_func_array",
    "forward_static_call",
];

fn is_superglobal_read(node: &AstNode) -> bool {
    match node.kind() {
        NodeKind::Identifier => SUPERGLOBALS.contains(&node.text()),
        _ if is_other(node.kind(), "subscript_expression") => {
            node.first_child().is_some_and(is_superglobal_read)
        }
        _ => false,
    }
}

/// Security hotspot: calling a function whose *name* comes directly from
/// request data — `$_GET['f']()`, or `call_user_func($_GET['f'])` — lets an
/// attacker choose which function in the whole program runs. This is far
/// more dangerous than it looks: it isn't limited to functions the
/// developer intended to expose, so an attacker who can steer this value
/// can call unrelated internal helpers (or `system`, if it's reachable)
/// with attacker-chosen arguments too.
pub struct DynamicFunctionCallRule {
    id: RuleId,
}

impl DynamicFunctionCallRule {
    pub fn new() -> Self {
        Self {
            id: RuleId::new("php:dynamic-function-call-from-superglobal").expect("valid rule id"),
        }
    }
}

impl Default for DynamicFunctionCallRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for DynamicFunctionCallRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn applies_to(&self, language: &LanguageIdentifier) -> bool {
        *language == LanguageIdentifier::php()
    }

    fn default_severity(&self) -> Severity {
        Severity::Blocker
    }

    fn issue_type(&self) -> IssueType {
        IssueType::Vulnerability
    }

    fn remediation_effort_minutes(&self) -> u32 {
        25
    }

    fn metadata(&self) -> yunq_rules_engine::RuleMetadata {
        yunq_rules_engine::RuleMetadata {
            description: "The function to call is read directly from request data (a \
                superglobal), letting an attacker choose which function in the program runs \
                with attacker-chosen arguments. Validate against an explicit allow-list of \
                function names before calling, or restructure to avoid a request-controlled \
                callable entirely."
                .into(),
            tags: vec!["security".into(), "injection".into(), "php".into()],
            cwe: Some(94),
            produces_hotspots: true,
        }
    }

    fn check(&self, _file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        ast.descendants()
            .filter(|n| *n.kind() == NodeKind::Call)
            .filter_map(|call| {
                let callee = callee_node(call)?;
                // `$_GET['f']()` — the callee itself is the superglobal read.
                if is_superglobal_read(callee) {
                    return Some(call);
                }
                // `call_user_func($_GET['f'], ...)` / `call_user_func_array(...)`.
                if *callee.kind() == NodeKind::Identifier
                    && DYNAMIC_CALL_FUNCTIONS.contains(&callee.text())
                {
                    let args = call
                        .children()
                        .iter()
                        .find(|c| is_other(c.kind(), "arguments"))?;
                    let first = args.children().first()?;
                    if first.descendants().any(is_superglobal_read) {
                        return Some(call);
                    }
                }
                None
            })
            .map(|call| {
                Finding::hotspot(
                    "the function called here is chosen by request data; confirm it's \
                    validated against an explicit allow-list first",
                    call.span(),
                )
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use yunq_ast::SourceFile;
    use yunq_rules_engine::AstParser;

    use super::*;

    fn check(code: &str) -> Vec<Finding> {
        let file = SourceFile::new("t.php", code, LanguageIdentifier::php()).unwrap();
        let ast = yunq_parser_php::PhpParser::new().parse(&file).unwrap();
        DynamicFunctionCallRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_direct_superglobal_call() {
        assert_eq!(check("<?php\n$_GET['f']();\n").len(), 1);
    }

    #[test]
    fn flags_call_user_func_on_superglobal() {
        assert_eq!(check("<?php\ncall_user_func($_GET['f']);\n").len(), 1);
    }

    #[test]
    fn ignores_call_user_func_on_fixed_name() {
        assert!(check("<?php\ncall_user_func('strlen', $s);\n").is_empty());
    }

    #[test]
    fn ignores_ordinary_calls() {
        assert!(check("<?php\nstrlen($s);\n").is_empty());
    }
}
