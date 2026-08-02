//! Rule: flags an `<html>` root element without a `lang` attribute (WCAG
//! 3.1.1 Language of Page) — assistive technology cannot pick the right
//! pronunciation/translation rules without it.

use vord_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use vord_rules_engine::{Finding, Rule, RuleId, RuleMetadata, Severity};

pub struct MissingLangAttributeRule {
    id: RuleId,
}

impl MissingLangAttributeRule {
    pub fn new() -> Self {
        Self {
            id: RuleId::new("a11y:missing-lang-attribute").expect("valid rule id"),
        } // vord-ignore: secrets:high-entropy-string (rule id, not a secret)
    }
}

impl Default for MissingLangAttributeRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for MissingLangAttributeRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn applies_to(&self, lang: &LanguageIdentifier) -> bool {
        *lang == LanguageIdentifier::html()
    }

    fn default_severity(&self) -> Severity {
        Severity::Minor
    }

    fn metadata(&self) -> RuleMetadata {
        RuleMetadata {
            description: "The `<html>` root element must declare a `lang` attribute so assistive technology and translators know the page's language (WCAG 3.1.1 Language of Page).".into(),
            tags: vec!["accessibility".into(), "a11y".into(), "wcag-3.1.1".into()],
            cwe: None,
            produces_hotspots: false,
        }
    }

    fn check(&self, file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        if ast.kind() != &NodeKind::SourceUnit {
            return Vec::new();
        }

        let content = file.content();
        let lower = content.to_ascii_lowercase();
        let Some(start) = lower.find("<html") else {
            return Vec::new();
        };
        let after_tag_name = start + 5;
        let starts_the_root_tag = matches!(
            lower[after_tag_name..].chars().next(),
            Some(c) if c.is_whitespace() || c == '>'
        );
        if !starts_the_root_tag {
            return Vec::new();
        }

        let end = lower[start..]
            .find('>')
            .map(|i| start + i + 1)
            .unwrap_or(content.len());
        let tag_text = &lower[start..end];
        if tag_text.contains("lang=") {
            return Vec::new();
        }

        let line = 1 + content[..start].matches('\n').count() as u32;
        vec![Finding::new(
            "`<html>` root element is missing a `lang` attribute; assistive technology cannot determine the page language",
            vord_ast::Span::new(line, 1, line, tag_text.len().max(1) as u32),
        )]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn source_unit(code: &str) -> AstNode {
        AstNode::new(
            NodeKind::SourceUnit,
            vord_ast::Span::new(1, 1, 1, code.len() as u32),
            code,
            vec![],
        )
    }

    #[test]
    fn flags_html_without_lang() {
        let code = "<html>\n<head></head>\n<body></body>\n</html>\n";
        let file = SourceFile::new("index.html", code, LanguageIdentifier::html()).unwrap();
        let findings = MissingLangAttributeRule::new().check(&file, &source_unit(code));
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn allows_html_with_lang() {
        let code = "<html lang=\"en\">\n<head></head>\n</html>\n";
        let file = SourceFile::new("index.html", code, LanguageIdentifier::html()).unwrap();
        let findings = MissingLangAttributeRule::new().check(&file, &source_unit(code));
        assert!(findings.is_empty());
    }

    #[test]
    fn ignores_files_without_an_html_root() {
        let code = "<div>fragment</div>\n";
        let file = SourceFile::new("fragment.html", code, LanguageIdentifier::html()).unwrap();
        let findings = MissingLangAttributeRule::new().check(&file, &source_unit(code));
        assert!(findings.is_empty());
    }
}
