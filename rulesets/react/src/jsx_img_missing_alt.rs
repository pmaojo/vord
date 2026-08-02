//! Rule: flags a JSX `<img>` with no `alt` attribute (WCAG 1.1.1 Non-text
//! Content). The HTML-only `a11y:img-missing-alt` rule never sees these —
//! JSX in `.tsx`/`.jsx` files is TypeScript, not HTML, in this analyzer's
//! language model.

use vord_ast::{AstNode, LanguageIdentifier, SourceFile};
use vord_rules_engine::{Finding, Rule, RuleId, RuleMetadata, Severity};

use crate::common::{find_attribute, tag_name};

pub struct JsxImgMissingAltRule {
    id: RuleId,
}

impl JsxImgMissingAltRule {
    pub fn new() -> Self {
        Self {
            id: RuleId::new("react:jsx-img-missing-alt").expect("valid rule id"),
        }
    }
}

impl Default for JsxImgMissingAltRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for JsxImgMissingAltRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn applies_to(&self, lang: &LanguageIdentifier) -> bool {
        *lang == LanguageIdentifier::typescript()
    }

    fn default_severity(&self) -> Severity {
        Severity::Major
    }

    fn metadata(&self) -> RuleMetadata {
        RuleMetadata {
            description: "A JSX `<img>` has no `alt` attribute, so screen readers cannot describe it (WCAG 1.1.1 Non-text Content).".into(),
            tags: vec!["react".into(), "accessibility".into(), "a11y".into(), "wcag-1.1.1".into()],
            cwe: None,
            produces_hotspots: false,
        }
    }

    fn check(&self, _file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        ast.descendants()
            .filter(|n| tag_name(n) == Some("img"))
            .filter(|el| find_attribute(el, "alt").is_none())
            .map(|el| {
                Finding::new(
                    "JSX `<img>` is missing an `alt` attribute; screen readers cannot describe this image",
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
        JsxImgMissingAltRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_img_without_alt() {
        let findings = check("const el = <img src=\"logo.png\" />;\n");
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn allows_img_with_alt() {
        let findings = check("const el = <img src=\"logo.png\" alt=\"Logo\" />;\n");
        assert!(findings.is_empty());
    }

    #[test]
    fn allows_img_with_empty_decorative_alt() {
        let findings = check("const el = <img src=\"deco.png\" alt=\"\" />;\n");
        assert!(findings.is_empty());
    }
}
