//! Rule: flags `<img>` tags without an `alt` attribute (WCAG 1.1.1
//! Non-text Content) — screen readers have nothing to announce for them.

use yunq_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use yunq_rules_engine::{Finding, Rule, RuleId, RuleMetadata, Severity};

pub struct ImgMissingAltRule {
    id: RuleId,
}

impl ImgMissingAltRule {
    pub fn new() -> Self {
        Self { id: RuleId::new("a11y:img-missing-alt").expect("valid rule id") }
    }
}

impl Default for ImgMissingAltRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for ImgMissingAltRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn applies_to(&self, lang: &LanguageIdentifier) -> bool {
        *lang == LanguageIdentifier::html()
    }

    fn default_severity(&self) -> Severity {
        Severity::Major
    }

    fn metadata(&self) -> RuleMetadata {
        RuleMetadata {
            description: "Images must have an `alt` attribute so screen readers can describe them (WCAG 1.1.1 Non-text Content).".into(),
            tags: vec!["accessibility".into(), "a11y".into(), "wcag-1.1.1".into()],
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
        let mut findings = Vec::new();
        let mut cursor = 0usize;

        while let Some(rel) = lower[cursor..].find("<img") {
            let start = cursor + rel;
            let after_tag_name = start + 4;
            let starts_a_tag = matches!(
                lower[after_tag_name..].chars().next(),
                Some(c) if c.is_whitespace() || c == '/' || c == '>'
            );
            if !starts_a_tag {
                cursor = after_tag_name;
                continue;
            }

            let end = lower[start..].find('>').map(|i| start + i + 1).unwrap_or(content.len());
            let tag_text = &lower[start..end];
            if !tag_text.contains("alt=") {
                let line = 1 + content[..start].matches('\n').count() as u32;
                findings.push(Finding::new(
                    "`<img>` is missing an `alt` attribute; screen readers cannot describe this image",
                    yunq_ast::Span::new(line, 1, line, tag_text.len().max(1) as u32),
                ));
            }
            cursor = end.max(after_tag_name);
        }
        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn source_unit(code: &str) -> AstNode {
        AstNode::new(NodeKind::SourceUnit, yunq_ast::Span::new(1, 1, 1, code.len() as u32), code, vec![])
    }

    #[test]
    fn flags_img_without_alt() {
        let code = "<body>\n<img src=\"logo.png\">\n</body>\n";
        let file = SourceFile::new("index.html", code, LanguageIdentifier::html()).unwrap();
        let findings = ImgMissingAltRule::new().check(&file, &source_unit(code));
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].span.start_line, 2);
    }

    #[test]
    fn flags_self_closing_img_without_alt() {
        let code = "<img src=\"x.png\" />\n";
        let file = SourceFile::new("index.html", code, LanguageIdentifier::html()).unwrap();
        let findings = ImgMissingAltRule::new().check(&file, &source_unit(code));
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn allows_img_with_alt() {
        let code = "<img src=\"logo.png\" alt=\"Company logo\">\n";
        let file = SourceFile::new("index.html", code, LanguageIdentifier::html()).unwrap();
        let findings = ImgMissingAltRule::new().check(&file, &source_unit(code));
        assert!(findings.is_empty());
    }

    #[test]
    fn counts_multiple_tags_independently() {
        let code = "<img src=\"a.png\">\n<img src=\"b.png\" alt=\"b\">\n<img src=\"c.png\">\n";
        let file = SourceFile::new("index.html", code, LanguageIdentifier::html()).unwrap();
        let findings = ImgMissingAltRule::new().check(&file, &source_unit(code));
        assert_eq!(findings.len(), 2);
    }

    #[test]
    fn applies_only_to_html() {
        let rule = ImgMissingAltRule::new();
        assert!(rule.applies_to(&LanguageIdentifier::html()));
        assert!(!rule.applies_to(&LanguageIdentifier::typescript()));
    }
}
