//! Rule: flags bare `window` references in favor of `globalThis`. `window`
//! only exists in browser contexts — it's `undefined` in Web Workers, Node,
//! and SSR — while `globalThis` resolves to the right global object
//! everywhere. Only the *receiver* position is checked (`window.foo`,
//! `typeof window`, ...); `foo.window` (a property named `window`) is left
//! alone, since that's an unrelated property access, not the global.

use vord_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use vord_rules_engine::{Finding, Rule, RuleId, RuleMetadata, Severity};

fn collect_window_identifiers<'a>(node: &'a AstNode, in_property_position: bool, out: &mut Vec<&'a AstNode>) {
    if *node.kind() == NodeKind::Identifier && node.text() == "window" && !in_property_position {
        out.push(node);
    }
    if *node.kind() == NodeKind::MemberAccess {
        let children = node.children();
        if let Some((last, rest)) = children.split_last() {
            for c in rest {
                collect_window_identifiers(c, false, out);
            }
            collect_window_identifiers(last, true, out);
        }
        return;
    }
    for c in node.children() {
        collect_window_identifiers(c, false, out);
    }
}

pub struct PreferGlobalThisOverWindowRule {
    id: RuleId,
}

impl PreferGlobalThisOverWindowRule {
    pub fn new() -> Self {
        Self {
            id: RuleId::new("typescript:prefer-globalthis-over-window").expect("valid rule id"),
        }
    }
}

impl Default for PreferGlobalThisOverWindowRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for PreferGlobalThisOverWindowRule {
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
            description: "`window` only exists in browser contexts and is `undefined` in Web Workers, Node, and SSR; `globalThis` resolves to the right global object in every environment.".into(),
            tags: vec!["typescript".into(), "portability".into()],
            cwe: None,
            produces_hotspots: false,
        }
    }

    fn check(&self, _file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        let mut nodes = Vec::new();
        collect_window_identifiers(ast, false, &mut nodes);
        nodes
            .into_iter()
            .map(|n| {
                Finding::new(
                    "prefer `globalThis` over `window` for portability across Web Workers, Node, and SSR",
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
        PreferGlobalThisOverWindowRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_window_member_access() {
        assert_eq!(check("window.addEventListener('x', y);\n").len(), 1);
    }

    #[test]
    fn flags_bare_window_in_typeof() {
        assert_eq!(check("if (typeof window !== 'undefined') {}\n").len(), 1);
    }

    #[test]
    fn allows_globalthis() {
        assert!(check("globalThis.addEventListener('x', y);\n").is_empty());
    }

    #[test]
    fn allows_window_as_property_name() {
        assert!(check("foo.window.close();\n").is_empty());
    }
}
