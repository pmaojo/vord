//! Rule: flags a string-literal default/fallback value passed as a `t(...)`
//! call's second argument — `t('greeting', 'Hola')`. Review feedback
//! (`MessageList.tsx`) called this out twice: a hardcoded fallback is a
//! hardcoded string with extra steps — it ships untranslated text the
//! moment the key is missing, in whichever language the author happened to
//! type it in. The translation catalog, not the call site, is where a
//! missing-key fallback belongs.

use vord_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use vord_rules_engine::{Finding, IssueType, Rule, RuleId, RuleMetadata, Severity};

use crate::common::call_arguments;

/// The callee name for a `t(...)` or `i18n.t(...)` call.
fn t_call_name(node: &AstNode) -> Option<&str> {
    if *node.kind() != NodeKind::Call {
        return None;
    }
    let callee = node.first_child()?;
    match callee.kind() {
        NodeKind::Identifier if callee.text() == "t" => Some("t"),
        NodeKind::MemberAccess => {
            let [object, prop] = callee.children() else {
                return None;
            };
            (*object.kind() == NodeKind::Identifier
                && object.text() == "i18n"
                && prop.text() == "t")
                .then_some("i18n.t")
        }
        _ => None,
    }
}

pub struct I18nHardcodedFallbackRule {
    id: RuleId,
}

impl I18nHardcodedFallbackRule {
    pub fn new() -> Self {
        Self {
            id: RuleId::new("react:i18n-hardcoded-fallback").expect("valid rule id"),
        }
    }
}

impl Default for I18nHardcodedFallbackRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for I18nHardcodedFallbackRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn applies_to(&self, lang: &LanguageIdentifier) -> bool {
        lang.is_typescript() || lang.is_javascript()
    }

    fn default_severity(&self) -> Severity {
        Severity::Minor
    }

    fn issue_type(&self) -> IssueType {
        IssueType::CodeSmell
    }

    fn metadata(&self) -> RuleMetadata {
        RuleMetadata {
            description: "A `t(...)`/`i18n.t(...)` call's second argument is a hardcoded string literal used as a default; a missing translation key should be handled in the catalog, not with an untranslated fallback at the call site.".into(),
            tags: vec!["react".into(), "i18n".into(), "correctness".into()],
            cwe: None,
            produces_hotspots: false,
        }
    }

    fn check(&self, file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        if vord_rules_engine::is_test_only_path(file.path()) {
            return Vec::new();
        }
        ast.descendants()
            .filter_map(|call| t_call_name(call).map(|name| (name, call)))
            .filter_map(|(name, call)| {
                let args = call_arguments(call);
                let second = args.get(1)?;
                (*second.kind() == NodeKind::StringLiteral).then_some((name, second))
            })
            .map(|(name, arg)| {
                Finding::new(
                    format!(
                        "`{name}(..., {})` hardcodes a fallback string; add the key to the translation catalog instead of defaulting to literal text",
                        arg.text()
                    ),
                    arg.span(),
                )
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vord_rules_engine::AstParser;

    fn check(code: &str) -> Vec<Finding> {
        let file =
            SourceFile::new("MessageList.tsx", code, LanguageIdentifier::typescript()).unwrap();
        let ast = vord_parser_typescript::TypeScriptParser::new()
            .parse(&file)
            .unwrap();
        I18nHardcodedFallbackRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_hardcoded_fallback_on_t() {
        let findings = check("const label = t('greeting', 'Hola');\n");
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("Hola"));
    }

    #[test]
    fn flags_hardcoded_fallback_on_i18n_t() {
        let findings = check("const label = i18n.t('greeting', 'Hola');\n");
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn allows_t_with_options_object() {
        let findings = check("const label = t('greeting', { count: 1 });\n");
        assert!(findings.is_empty());
    }

    #[test]
    fn allows_t_with_no_second_argument() {
        let findings = check("const label = t('greeting');\n");
        assert!(findings.is_empty());
    }
}
