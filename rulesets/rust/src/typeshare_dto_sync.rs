use vord_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use vord_rules_engine::{declare_rule_id, Finding, IssueType, Rule, RuleId, Severity};

use crate::common::is_other;

declare_rule_id!(TypeshareDtoSyncRule, "rust:typeshare-dto-sync");

impl Rule for TypeshareDtoSyncRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn applies_to(&self, language: &LanguageIdentifier) -> bool {
        *language == LanguageIdentifier::rust()
    }

    fn default_severity(&self) -> Severity {
        Severity::Major
    }

    fn issue_type(&self) -> IssueType {
        IssueType::Bug
    }

    fn remediation_effort_minutes(&self) -> u32 {
        5
    }

    fn metadata(&self) -> vord_rules_engine::RuleMetadata {
        vord_rules_engine::RuleMetadata {
            description: r#"Detects Rust structs annotated with `#[typeshare]` or `#[derive(..., Typeshare)]` that are missing `#[serde(rename_all = "...")]` attribute to ensure predictable field casing across language boundaries."#
                .into(),
            tags: vec!["rust".into(), "serialization".into(), "typeshare".into()],
            cwe: None,
            produces_hotspots: false,
        }
    }

    fn check(&self, _file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        let mut findings = Vec::new();

        for parent in ast.descendants() {
            let children = parent.children();
            for (idx, node) in children.iter().enumerate() {
                if !is_other(node.kind(), "struct_item") {
                    continue;
                }

                // Collect attribute nodes attached to this struct item
                let mut attrs = Vec::new();

                // Direct child attributes
                for child in node.children() {
                    if is_other(child.kind(), "attribute_item") {
                        attrs.push(child);
                    }
                }

                // Preceding sibling attributes
                for prev in children[..idx].iter().rev() {
                    if is_other(prev.kind(), "attribute_item") {
                        attrs.push(prev);
                    } else if *prev.kind() != NodeKind::Comment {
                        break;
                    }
                }

                let is_typeshare = attrs.iter().any(|a| is_typeshare_attr(a));
                if is_typeshare {
                    let has_serde_rename_all = attrs.iter().any(|a| is_serde_rename_all_attr(a));
                    if !has_serde_rename_all {
                        findings.push(Finding::new(
                            "Typeshare struct missing serde rename_all attribute to ensure predictable field casing across language boundaries",
                            node.span(),
                        ));
                    }
                }
            }
        }

        findings
    }
}

fn is_typeshare_attr(attr: &AstNode) -> bool {
    if !is_other(attr.kind(), "attribute_item") {
        return false;
    }
    let text = attr.text();
    let compact: String = text.chars().filter(|c| !c.is_whitespace()).collect();
    if compact.starts_with("#[typeshare") || compact.starts_with("#![typeshare") {
        return true;
    }
    if (compact.starts_with("#[derive") || compact.starts_with("#![derive")) && compact.contains("Typeshare") {
        return true;
    }
    false
}

fn is_serde_rename_all_attr(attr: &AstNode) -> bool {
    if !is_other(attr.kind(), "attribute_item") {
        return false;
    }
    let text = attr.text();
    let compact: String = text.chars().filter(|c| !c.is_whitespace()).collect();
    compact.contains("serde") && compact.contains("rename_all")
}

#[cfg(test)]
mod tests {
    use vord_ast::SourceFile;
    use vord_rules_engine::AstParser;

    use super::*;

    fn check(code: &str) -> Vec<Finding> {
        let file = SourceFile::new("t.rs", code, LanguageIdentifier::rust()).unwrap();
        let ast = vord_parser_rust::RustParser::new().parse(&file).unwrap();
        TypeshareDtoSyncRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_typeshare_struct_missing_serde_rename_all() {
        let findings = check("#[typeshare]\npub struct UserDto {\n    pub user_id: String,\n}\n");
        assert_eq!(findings.len(), 1);
        assert_eq!(
            findings[0].message,
            "Typeshare struct missing serde rename_all attribute to ensure predictable field casing across language boundaries"
        );
    }

    #[test]
    fn flags_derive_typeshare_struct_missing_serde_rename_all() {
        let findings = check("#[derive(Serialize, Deserialize, Typeshare)]\npub struct UserDto {\n    pub user_id: String,\n}\n");
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn ignores_typeshare_struct_with_serde_rename_all() {
        let findings = check("#[typeshare]\n#[serde(rename_all = \"camelCase\")]\npub struct UserDto {\n    pub user_id: String,\n}\n");
        assert!(findings.is_empty());
    }

    #[test]
    fn ignores_derive_typeshare_struct_with_serde_rename_all() {
        let findings = check("#[derive(Serialize, Deserialize, Typeshare)]\n#[serde(rename_all = \"snake_case\")]\npub struct UserDto {\n    pub user_id: String,\n}\n");
        assert!(findings.is_empty());
    }

    #[test]
    fn ignores_non_typeshare_struct() {
        let findings = check("#[derive(Serialize, Deserialize)]\npub struct InternalDto {\n    pub internal_id: u64,\n}\n");
        assert!(findings.is_empty());
    }

    #[test]
    fn ignores_plain_struct() {
        let findings = check("pub struct Plain {\n    pub id: u32,\n}\n");
        assert!(findings.is_empty());
    }
}
