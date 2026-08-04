//! Rule: flags `.sort()` calls with no comparator. Array#sort's default
//! comparator converts elements to strings and orders them by UTF-16 code
//! unit, so `[10, 2, 1].sort()` yields `[1, 10, 2]` — rarely what the
//! caller wants, and for strings it means the result silently depends on
//! case and locale instead of `String#localeCompare`.

use vord_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use vord_rules_engine::{Finding, IssueType, Rule, RuleId, RuleMetadata, Severity};

use crate::common::call_arguments;

fn flagged_call(node: &AstNode) -> Option<&AstNode> {
    if *node.kind() != NodeKind::Call {
        return None;
    }
    let callee = node.first_child()?;
    if *callee.kind() != NodeKind::MemberAccess {
        return None;
    }
    let property = callee.children().last()?;
    if !(*property.kind() == NodeKind::Identifier && property.text() == "sort") {
        return None;
    }
    call_arguments(node).is_empty().then_some(node)
}

pub struct SortWithoutCompareRule {
    id: RuleId,
}

impl SortWithoutCompareRule {
    pub fn new() -> Self {
        Self {
            id: RuleId::new("typescript:sort-without-compare").expect("valid rule id"),
        }
    }
}

impl Default for SortWithoutCompareRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for SortWithoutCompareRule {
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

    fn metadata(&self) -> RuleMetadata {
        RuleMetadata {
            description: "`.sort()` with no comparator falls back to converting elements to strings and ordering by UTF-16 code unit; provide an explicit compare function (e.g. `(a, b) => a.localeCompare(b)` for strings) so the ordering is reliable.".into(),
            tags: vec!["typescript".into(), "pitfall".into()],
            cwe: None,
            produces_hotspots: false,
        }
    }

    fn check(&self, _file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        ast.descendants()
            .filter_map(flagged_call)
            .map(|n| {
                Finding::new(
                    "`.sort()` with no comparator uses default string ordering; provide an explicit compare function",
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
        SortWithoutCompareRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_bare_sort() {
        assert_eq!(check("names.sort();\n").len(), 1);
    }

    #[test]
    fn allows_sort_with_localecompare() {
        assert!(check("names.sort((a, b) => a.localeCompare(b));\n").is_empty());
    }

    #[test]
    fn allows_sort_with_numeric_comparator() {
        assert!(check("nums.sort((a, b) => a - b);\n").is_empty());
    }

    #[test]
    fn allows_unrelated_sort_property() {
        assert!(check("cache.sort;\n").is_empty());
    }
}
