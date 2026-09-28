//! Rule: flags a TypeScript `enum` whose every member's string value is
//! just its own key quoted (`enum Status { Active = "Active", ... }`). This
//! pattern gives up the one thing a numeric or custom-valued enum buys over
//! a plain string: a value that can't accidentally match a raw string
//! typed by hand elsewhere but drifts from the member name. Since the
//! string values here are already identical to the keys, nothing is lost
//! by using a union of string literal types (`type Status = "Active" |
//! ...`) instead — which also erases cleanly, unlike a `string` enum.

use vord_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use vord_rules_engine::{Finding, IssueType, Rule, RuleId, RuleMetadata, Severity};

use crate::common::is_other;

fn unwrap_quotes(text: &str) -> &str {
    text.trim_matches(|c| c == '"' || c == '\'' || c == '`')
}

fn member_matches_key(assignment: &AstNode) -> bool {
    let [name, value] = assignment.children() else {
        return false;
    };
    *value.kind() == NodeKind::StringLiteral && unwrap_quotes(value.text()) == name.text()
}

fn flagged(enum_decl: &AstNode) -> bool {
    let Some(body) = enum_decl.children().iter().find(|c| is_other(c, "enum_body")) else {
        return false;
    };
    let members: Vec<&AstNode> = body
        .children()
        .iter()
        .filter(|c| is_other(c, "enum_assignment"))
        .collect();
    !members.is_empty() && members.iter().all(|m| member_matches_key(m))
}

pub struct EnumStringlyTypedRule {
    id: RuleId,
}

impl EnumStringlyTypedRule {
    pub fn new() -> Self {
        Self {
            id: RuleId::new("typescript:enum-stringly-typed").expect("valid rule id"),
        }
    }
}

impl Default for EnumStringlyTypedRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for EnumStringlyTypedRule {
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
        10
    }

    fn metadata(&self) -> RuleMetadata {
        RuleMetadata {
            description: "Every member of this enum is assigned a string identical to its own key, so it gains nothing over a union of string literal types — which also erases cleanly at compile time, unlike a string enum.".into(),
            tags: vec!["typescript".into(), "clarity".into()],
            cwe: None,
            produces_hotspots: false,
        }
    }

    fn check(&self, _file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        ast.descendants()
            .filter(|n| is_other(n, "enum_declaration"))
            .filter(|n| flagged(n))
            .map(|n| {
                Finding::new(
                    "every member of this enum duplicates its key as a string value; use a union of string literal types instead",
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
        EnumStringlyTypedRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_enum_where_every_member_mirrors_its_key() {
        assert_eq!(check("enum Status { Active = \"Active\", Inactive = \"Inactive\" }\n").len(), 1);
    }

    #[test]
    fn allows_enum_with_custom_string_values() {
        assert!(check("enum Status { Active = \"A\", Inactive = \"I\" }\n").is_empty());
    }

    #[test]
    fn allows_numeric_enum() {
        assert!(check("enum Status { Active, Inactive }\n").is_empty());
    }

    #[test]
    fn allows_partially_mirrored_enum() {
        assert!(check("enum Status { Active = \"Active\", Inactive = \"I\" }\n").is_empty());
    }

    #[test]
    fn allows_enum_with_explicit_numeric_values() {
        assert!(check("enum Status { Active = 1, Inactive = 2 }\n").is_empty());
    }
}
