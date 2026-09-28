//! Rule: flags `string.match(regex)` where `regex` is a literal without the
//! global (`g`) flag — with no `g` flag, `.match()` returns the same single
//! match info `regex.exec(string)` does, except `.exec()` states the
//! regex-first, single-match intent directly instead of leaving it implicit
//! in which method happens to be on `String.prototype`.

use vord_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use vord_rules_engine::{Finding, Rule, RuleId, RuleMetadata, Severity};

use crate::common::{call_arguments, is_other};

fn is_non_global_regex_literal(arg: &AstNode) -> bool {
    if !is_other(arg, "regex") {
        return false;
    }
    !arg
        .children()
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
    if !(*property.kind() == NodeKind::Identifier && property.text() == "match") {
        return None;
    }
    let pattern = call_arguments(node).first()?;
    is_non_global_regex_literal(pattern).then_some(node)
}

pub struct PreferRegExpExecRule {
    id: RuleId,
}

impl PreferRegExpExecRule {
    pub fn new() -> Self {
        Self {
            id: RuleId::new("typescript:prefer-regexp-exec").expect("valid rule id"),
        }
    }
}

impl Default for PreferRegExpExecRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for PreferRegExpExecRule {
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
        5
    }

    fn metadata(&self) -> RuleMetadata {
        RuleMetadata {
            description: "`String#match()` with a non-global regex returns the same single match info as `RegExp#exec()`; use `regex.exec(string)` to make the single-match intent explicit.".into(),
            tags: vec!["typescript".into(), "clarity".into(), "regex".into()],
            cwe: None,
            produces_hotspots: false,
        }
    }

    fn check(&self, _file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        ast.descendants()
            .filter_map(flagged_call)
            .map(|n| Finding::new("use the `RegExp.exec()` method instead", n.span()))
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
        PreferRegExpExecRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_match_with_non_global_regex() {
        assert_eq!(check("s.match(/foo/);\n").len(), 1);
    }

    #[test]
    fn allows_match_with_global_regex() {
        assert!(check("s.match(/foo/g);\n").is_empty());
    }

    #[test]
    fn allows_match_with_string_pattern() {
        assert!(check("s.match('foo');\n").is_empty());
    }

    #[test]
    fn allows_exec_call() {
        assert!(check("/foo/.exec(s);\n").is_empty());
    }
}
