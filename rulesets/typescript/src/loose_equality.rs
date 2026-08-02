//! Rule: flags `==`/`!=` in favor of `===`/`!==`. Loose (in)equality coerces
//! operand types before comparing (`0 == "" `, `null == undefined`, `[] ==
//! false`), producing surprising results the strict operators don't; there
//! is essentially never a reason to prefer the coercing form.

use vord_ast::{AstNode, LanguageIdentifier, SourceFile};
use vord_rules_engine::{Finding, IssueType, Rule, RuleId, RuleMetadata, Severity};

use crate::common::is_other;

/// tree-sitter's `named_children` drops the anonymous operator token, so
/// `binary_expression`'s only named children are its two operands. Recover
/// the operator from the raw source gap between them (same technique
/// `smells:cognitive-complexity` uses for `&&`/`||`).
fn loose_operator(node: &AstNode) -> Option<&'static str> {
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
        "==" => Some("=="),
        "!=" => Some("!="),
        _ => None,
    }
}

pub struct LooseEqualityRule {
    id: RuleId,
}

impl LooseEqualityRule {
    pub fn new() -> Self {
        Self {
            id: RuleId::new("typescript:loose-equality").expect("valid rule id"),
        }
    }
}

impl Default for LooseEqualityRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for LooseEqualityRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn applies_to(&self, lang: &LanguageIdentifier) -> bool {
        *lang == LanguageIdentifier::typescript()
    }

    fn default_severity(&self) -> Severity {
        Severity::Minor
    }

    fn issue_type(&self) -> IssueType {
        IssueType::CodeSmell
    }

    fn remediation_effort_minutes(&self) -> u32 {
        2
    }

    fn metadata(&self) -> RuleMetadata {
        RuleMetadata {
            description: "`==`/`!=` coerce operand types before comparing, producing surprising results (`0 == ''`, `null == undefined`); use `===`/`!==` instead.".into(),
            tags: vec!["typescript".into(), "pitfall".into()],
            cwe: None,
            produces_hotspots: false,
        }
    }

    fn check(&self, _file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        ast.descendants()
            .filter_map(|n| loose_operator(n).map(|op| (n, op)))
            .map(|(n, op)| {
                let strict = if op == "==" { "===" } else { "!==" };
                Finding::new(
                    format!("`{op}` performs type coercion; use `{strict}` instead"),
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
        LooseEqualityRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_loose_equality() {
        let findings = check("if (a == b) {}\n");
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("==="));
    }

    #[test]
    fn flags_loose_inequality() {
        let findings = check("if (a != b) {}\n");
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("!=="));
    }

    #[test]
    fn allows_strict_equality() {
        assert!(check("if (a === b) {}\n").is_empty());
    }

    #[test]
    fn allows_strict_inequality() {
        assert!(check("if (a !== b) {}\n").is_empty());
    }
}
