//! Rule: flags regex literals whose pattern nests a quantified group inside
//! another quantifier — `(a+)+`, `(a*)*`, `(.*)*`, ... — the classic
//! catastrophic-backtracking (ReDoS) shape: a failed match can force the
//! engine to retry exponentially many ways of splitting the inner
//! repetition among the outer one. tree-sitter-typescript hands back a
//! regex's pattern as a single opaque `regex_pattern` leaf (it doesn't
//! parse regex syntax itself), so detection is a small hand-rolled scan
//! over that text rather than an AST match.

use vord_ast::{AstNode, LanguageIdentifier, SourceFile};
use vord_rules_engine::{Finding, IssueType, Rule, RuleId, RuleMetadata, Severity};

use crate::common::is_other;

/// Scans a regex pattern's raw source for a group that both contains a
/// `+`/`*` quantifier and is itself immediately followed by a `+`/`*`
/// quantifier — e.g. the `(a+)+` in `/(a+)+b/`. Tracks one "did this group
/// see a quantifier while open" flag per nesting level and skips `[...]`
/// character classes and `\`-escaped characters, where `+`/`*` are literal.
fn has_nested_quantifier(pattern: &str) -> bool {
    let mut group_had_quantifier: Vec<bool> = Vec::new();
    let mut last_closed_had_quantifier: Option<bool> = None;
    let mut in_class = false;
    let mut escaped = false;

    for b in pattern.bytes() {
        if escaped {
            escaped = false;
            continue;
        }
        match b {
            b'\\' => escaped = true,
            b'[' if !in_class => in_class = true,
            b']' if in_class => in_class = false,
            b'(' if !in_class => {
                group_had_quantifier.push(false);
                last_closed_had_quantifier = None;
            }
            b')' if !in_class => {
                last_closed_had_quantifier = Some(group_had_quantifier.pop().unwrap_or(false));
            }
            b'+' | b'*' if !in_class => {
                if last_closed_had_quantifier == Some(true) {
                    return true;
                }
                if let Some(top) = group_had_quantifier.last_mut() {
                    *top = true;
                }
                last_closed_had_quantifier = None;
            }
            _ => last_closed_had_quantifier = None,
        }
    }
    false
}

pub struct RedosNestedQuantifierRule {
    id: RuleId,
}

impl RedosNestedQuantifierRule {
    pub fn new() -> Self {
        Self {
            id: RuleId::new("typescript:redos-nested-quantifier").expect("valid rule id"),
        }
    }
}

impl Default for RedosNestedQuantifierRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for RedosNestedQuantifierRule {
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
        IssueType::Vulnerability
    }

    fn metadata(&self) -> RuleMetadata {
        RuleMetadata {
            description: "A quantified group nested inside another quantifier (e.g. `(a+)+`) can force the regex engine into exponential backtracking on a failed match — a denial-of-service (ReDoS) risk for any input the pattern is run against.".into(),
            tags: vec!["typescript".into(), "security".into(), "regex".into(), "denial-of-service".into()],
            cwe: Some(1333),
            produces_hotspots: false,
        }
    }

    fn check(&self, _file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        ast.descendants()
            .filter(|n| is_other(n, "regex_pattern"))
            .filter(|n| has_nested_quantifier(n.text()))
            .map(|n| Finding::new(format!("regex `/{}/` nests a quantified group inside another quantifier, which can cause catastrophic backtracking (ReDoS)", n.text()), n.span()))
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
        RedosNestedQuantifierRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_plus_nested_in_plus() {
        assert_eq!(check("const r = /(a+)+b/;\n").len(), 1);
    }

    #[test]
    fn flags_star_nested_in_star() {
        assert_eq!(check("const r = /(.*)*b/;\n").len(), 1);
    }

    #[test]
    fn allows_single_quantified_group() {
        assert!(check("const r = /(ab)+c/;\n").is_empty());
    }

    #[test]
    fn allows_plain_regex() {
        assert!(check("const r = /^[a-z]+$/;\n").is_empty());
    }

    #[test]
    fn allows_quantifier_inside_character_class() {
        assert!(check("const r = /[a+*]+/;\n").is_empty());
    }

    #[test]
    fn direct_pattern_check_flags_nested_quantifier() {
        assert!(has_nested_quantifier("(a+)+"));
        assert!(!has_nested_quantifier("(ab)+"));
        assert!(!has_nested_quantifier("abc"));
    }
}
