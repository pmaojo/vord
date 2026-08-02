//! Rule: flags `<a target="_blank">` without `rel="noopener"` (or
//! `noreferrer`, which implies it). The opened page gets a `window.opener`
//! handle back to the origin tab and can navigate it elsewhere — reverse
//! tabnabbing (CWE-1022).

use vord_ast::{AstNode, LanguageIdentifier, SourceFile};
use vord_rules_engine::{Finding, IssueType, Rule, RuleId, RuleMetadata, Severity};

use crate::common::{attribute_value, find_attribute, tag_name};

fn string_attr_value(el: &AstNode, name: &str) -> Option<String> {
    let attr = find_attribute(el, name)?;
    let value = attribute_value(attr)?;
    Some(value.text().trim_matches(['"', '\'']).to_string())
}

pub struct UnsafeTargetBlankRule {
    id: RuleId,
}

impl UnsafeTargetBlankRule {
    pub fn new() -> Self {
        Self {
            id: RuleId::new("react:unsafe-target-blank").expect("valid rule id"),
        }
    }
}

impl Default for UnsafeTargetBlankRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for UnsafeTargetBlankRule {
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
            description: "`<a target=\"_blank\">` without `rel=\"noopener\"` lets the opened page access `window.opener` and redirect the original tab (reverse tabnabbing).".into(),
            tags: vec!["react".into(), "security".into()],
            cwe: Some(1022),
            produces_hotspots: false,
        }
    }

    fn check(&self, _file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        ast.descendants()
            .filter(|n| tag_name(n) == Some("a"))
            .filter(|el| string_attr_value(el, "target").as_deref() == Some("_blank"))
            .filter(|el| {
                let rel = string_attr_value(el, "rel").unwrap_or_default();
                !rel.contains("noopener") && !rel.contains("noreferrer")
            })
            .map(|el| {
                Finding::new(
                    "`target=\"_blank\"` without `rel=\"noopener\"` lets the opened page access `window.opener` and redirect this tab",
                    el.span(),
                )
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vord_ast::SourceFile;
    use vord_rules_engine::AstParser;

    fn check(code: &str) -> Vec<Finding> {
        let file = SourceFile::new("t.tsx", code, LanguageIdentifier::typescript()).unwrap();
        let ast = vord_parser_typescript::TypeScriptParser::new()
            .parse(&file)
            .unwrap();
        UnsafeTargetBlankRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_target_blank_without_rel() {
        let findings = check("const el = <a href=\"https://x.com\" target=\"_blank\">go</a>;\n");
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn allows_target_blank_with_noopener() {
        let findings = check(
            "const el = <a href=\"https://x.com\" target=\"_blank\" rel=\"noopener\">go</a>;\n",
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn allows_target_blank_with_noreferrer() {
        let findings = check(
            "const el = <a href=\"https://x.com\" target=\"_blank\" rel=\"noreferrer\">go</a>;\n",
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn ignores_links_without_target_blank() {
        let findings = check("const el = <a href=\"/local\">go</a>;\n");
        assert!(findings.is_empty());
    }

    #[test]
    fn ignores_non_anchor_elements() {
        let findings = check("const el = <div target=\"_blank\">go</div>;\n");
        assert!(findings.is_empty());
    }
}
