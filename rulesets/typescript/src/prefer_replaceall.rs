//! Rule: flags `String#replace(pattern, ...)` calls whose pattern is a
//! regex literal with the global (`g`) flag — `String#replaceAll()`
//! expresses the same "replace every match" intent directly, without
//! relying on a regex flag a reader has to notice to understand the call
//! replaces more than the first match.

use vord_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use vord_rules_engine::{Finding, Rule, RuleId, RuleMetadata, Severity};

use crate::common::{call_arguments, is_other};

fn is_global_regex(arg: &AstNode) -> bool {
    if !is_other(arg, "regex") {
        return false;
    }
    arg.children()
        .iter()
        .any(|c| is_other(c, "regex_flags") && c.text().contains('g'))
}

fn flagged_call(node: &AstNode) -> Option<&AstNode> {
    if *node.kind() != NodeKind::Call {
        return None;
    }
    let callee = node.first_child()?;
    if *callee.kind() != NodeKind::MemberAccess {
        return None;
    }
    let property = callee.children().last()?;
    if !(*property.kind() == NodeKind::Identifier && property.text() == "replace") {
        return None;
    }
    let pattern = call_arguments(node).first()?;
    is_global_regex(pattern).then_some(node)
}

pub struct PreferReplaceAllRule {
    id: RuleId,
}

impl PreferReplaceAllRule {
    pub fn new() -> Self {
        Self {
            id: RuleId::new("typescript:prefer-replaceall").expect("valid rule id"),
        }
    }
}

impl Default for PreferReplaceAllRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for PreferReplaceAllRule {
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
            description: "`.replace()` with a global (`g`) regex replaces every match, same as `.replaceAll()` — prefer `.replaceAll()` so the intent doesn't hinge on a regex flag.".into(),
            tags: vec!["typescript".into(), "clarity".into()],
            cwe: None,
            produces_hotspots: false,
        }
    }

    fn check(&self, _file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        ast.descendants()
            .filter_map(flagged_call)
            .map(|n| {
                Finding::new(
                    "`.replace()` with a global regex replaces every match; use `.replaceAll()` to express that directly",
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
        PreferReplaceAllRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_replace_with_global_regex() {
        assert_eq!(check("s.replace(/\\s/g, '');\n").len(), 1);
    }

    #[test]
    fn allows_replace_with_non_global_regex() {
        assert!(check("s.replace(/\\s/, '');\n").is_empty());
    }

    #[test]
    fn allows_replace_with_string_pattern() {
        assert!(check("s.replace('a', 'b');\n").is_empty());
    }

    #[test]
    fn allows_replaceall_call() {
        assert!(check("s.replaceAll(/\\s/g, '');\n").is_empty());
    }
}
