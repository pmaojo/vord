use vord_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use vord_rules_engine::{Finding, IssueType, Rule, RuleId, Severity};

use crate::common::is_other;

/// The function's declared signature — everything up to (not including) the
/// opening `{` of its body (or the whole text, for a body-less trait method
/// signature).
fn signature_text(node: &AstNode) -> &str {
    let text = node.text();
    text.find('{').map(|i| &text[..i]).unwrap_or(text)
}

/// Whether `token` (e.g. `"'a"`) occurs in `haystack` as a whole token —
/// not as a prefix of a longer lifetime name (`'abc` doesn't count as an
/// occurrence of `'a`).
fn token_occurs(haystack: &str, token: &str) -> bool {
    let mut idx = 0;
    while let Some(pos) = haystack.get(idx..).and_then(|h| h.find(token)) {
        let abs = idx + pos;
        let after = &haystack[abs + token.len()..];
        let boundary_ok = after
            .chars()
            .next()
            .is_none_or(|c| !c.is_alphanumeric() && c != '_');
        if boundary_ok {
            return true;
        }
        idx = abs + 1;
    }
    false
}

fn lifetime_params(fn_node: &AstNode) -> Vec<&AstNode> {
    let Some(type_params) = fn_node
        .children()
        .iter()
        .find(|c| is_other(c.kind(), "type_parameters"))
    else {
        return Vec::new();
    };
    type_params
        .children()
        .iter()
        .filter(|c| is_other(c.kind(), "lifetime_parameter"))
        .collect()
}

fn lifetime_name(lifetime_param: &AstNode) -> Option<&str> {
    lifetime_param
        .children()
        .iter()
        .find(|c| is_other(c.kind(), "lifetime"))
        .map(AstNode::text)
}

/// Whether `lifetime_param` (declared in `fn_node`'s generic parameter
/// list) is referenced anywhere after its own declaration in `fn_node`'s
/// signature — its parameters, return type, or where-clause, or a later
/// lifetime's bound (`'b: 'a`).
fn is_used_after_declaration(fn_node: &AstNode, lifetime_param: &AstNode, sig: &str) -> bool {
    let Some(name) = lifetime_name(lifetime_param) else {
        return true; // couldn't extract a name; don't risk a false positive
    };
    let fn_start = fn_node.byte_range().start;
    let rel_end = lifetime_param.byte_range().end.saturating_sub(fn_start);
    let Some(remainder) = sig.get(rel_end..) else {
        return true;
    };
    token_occurs(remainder, name)
}

/// A lifetime parameter declared on a `fn` but never named again in its
/// parameters, return type, or where-clause does nothing — it neither
/// constrains nor connects any borrows, and rustc's `unused_lifetimes`
/// lint (allow-by-default) won't catch it unless a project explicitly
/// enables it. Removing it (or, if elision was intended, just dropping the
/// explicit lifetime) simplifies the signature without changing behavior.
pub struct UnusedLifetimeParameterRule {
    id: RuleId,
}

impl UnusedLifetimeParameterRule {
    pub fn new() -> Self {
        Self {
            id: RuleId::new("rust:unused-lifetime-parameter").expect("valid rule id"),
        }
    }
}

impl Default for UnusedLifetimeParameterRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for UnusedLifetimeParameterRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn applies_to(&self, language: &LanguageIdentifier) -> bool {
        *language == LanguageIdentifier::rust()
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

    fn metadata(&self) -> vord_rules_engine::RuleMetadata {
        vord_rules_engine::RuleMetadata {
            description: "A lifetime parameter declared on a function but never referenced \
                again in its parameters, return type, or where-clause does nothing; remove \
                it to simplify the signature."
                .into(),
            tags: vec!["rust".into(), "readability".into()],
            cwe: None,
            produces_hotspots: false,
        }
    }

    fn check(&self, file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        let test_ranges = vord_rules_engine::rust_test_module_ranges(file.content());

        ast.descendants()
            .filter(|n| *n.kind() == NodeKind::FunctionDef)
            .filter(|n| !vord_rules_engine::in_ranges(&test_ranges, n.span().start_line))
            .flat_map(|fn_node| {
                let sig = signature_text(fn_node);
                lifetime_params(fn_node)
                    .into_iter()
                    .filter(move |lp| !is_used_after_declaration(fn_node, lp, sig))
                    .map(|lp| {
                        let name = lifetime_name(lp).unwrap_or("'?");
                        Finding::new(
                            format!(
                                "lifetime parameter `{name}` is declared but never used again \
                                in the signature"
                            ),
                            lp.span(),
                        )
                    })
                    .collect::<Vec<_>>()
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
        let file = SourceFile::new("t.rs", code, LanguageIdentifier::rust()).unwrap();
        let ast = vord_parser_rust::RustParser::new().parse(&file).unwrap();
        UnusedLifetimeParameterRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_unused_lifetime_with_unrelated_reference_param() {
        let findings = check("fn f<'a>(x: &str) -> usize { x.len() }\n");
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn flags_unused_lifetime_alongside_used_one() {
        let findings = check("fn f<'a, 'b>(x: &'a str, y: &str) -> &'a str { x }\n");
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("'b"));
    }

    #[test]
    fn ignores_lifetime_used_in_parameter() {
        assert!(check("fn f<'a>(x: &'a str) -> usize { x.len() }\n").is_empty());
    }

    #[test]
    fn ignores_lifetime_used_only_in_return_type() {
        assert!(check("fn f<'a>(x: &'a str) -> &'a str { x }\n").is_empty());
    }

    #[test]
    fn ignores_lifetime_used_in_where_clause_bound() {
        assert!(
            check("fn f<'a, T>(x: &'a T) -> &'a T where T: std::fmt::Debug { x }\n").is_empty()
        );
    }

    #[test]
    fn ignores_lifetime_referenced_by_a_later_lifetime_bound() {
        assert!(check("fn f<'a, 'b: 'a>(x: &'b str) -> &'a str { x }\n").is_empty());
    }

    #[test]
    fn ignores_fn_without_generics() {
        assert!(check("fn f(x: &str) -> usize { x.len() }\n").is_empty());
    }

    #[test]
    fn ignores_unused_lifetime_parameter_inside_a_cfg_test_module() {
        let code = "fn prod() {}\n\n#[cfg(test)]\nmod tests {\n    #[test]\n    fn t() {\n        fn f<'a>(x: &str) -> usize { x.len() }\n    }\n}\n";
        assert!(check(code).is_empty());
    }
}
