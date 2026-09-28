//! Rule: flags a `px` value used for text sizing — `fontSize`/`lineHeight`
//! in an inline `style={{...}}`, or a Tailwind arbitrary value
//! (`text-[14px]`, `leading-[20px]`) in a `className`. Pixel text doesn't
//! scale with the user's browser/OS font-size accessibility setting;
//! relative units (`rem`, or a Tailwind text-size utility like `text-sm`)
//! do. Repeated review feedback across this codebase's PRs (`ProposalModal`,
//! `Message`) settled on: text/measure sizing is always relative, never
//! `px`.

use vord_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use vord_rules_engine::{Finding, IssueType, Rule, RuleId, RuleMetadata, Severity};

use crate::common::{attribute_value, find_attribute, is_jsx_kind, is_other, jsx_expression_inner};

const TEXT_STYLE_PROPS: [&str; 2] = ["fontSize", "lineHeight"];
const TEXT_CLASS_PREFIXES: [&str; 2] = ["text-[", "leading-["];

fn has_px_value(text: &str) -> bool {
    let trimmed = text.trim();
    trimmed.ends_with("px")
        && trimmed[..trimmed.len() - 2]
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_digit() || c == '-')
}

/// `fontSize: '14px'` / `lineHeight: "20px"` pairs inside an inline
/// `style={{...}}` object.
fn flag_inline_style(el: &AstNode, out: &mut Vec<Finding>) {
    let Some(style_attr) = find_attribute(el, "style") else {
        return;
    };
    let Some(value) = attribute_value(style_attr) else {
        return;
    };
    let Some(expr) = jsx_expression_inner(value) else {
        return;
    };
    if !is_other(expr, "object") {
        return;
    }
    for pair in expr.children().iter().filter(|c| is_other(c, "pair")) {
        let [key, val] = pair.children() else {
            continue;
        };
        if !TEXT_STYLE_PROPS.contains(&key.text()) {
            continue;
        }
        if *val.kind() == NodeKind::StringLiteral
            && has_px_value(
                val.text()
                    .trim_matches(|c| c == '\'' || c == '"' || c == '`'),
            )
        {
            out.push(Finding::new(
                format!(
                    "`{}` uses a `px` value; use a relative unit (`rem`) so text scales with the user's font-size accessibility setting",
                    key.text()
                ),
                pair.span(),
            ));
        }
    }
}

/// `text-[14px]` / `leading-[20px]` tokens inside a `className`/`class`
/// string.
fn flag_class_list(el: &AstNode, out: &mut Vec<Finding>) {
    let Some(attr) = find_attribute(el, "className").or_else(|| find_attribute(el, "class")) else {
        return;
    };
    let Some(value) = attribute_value(attr) else {
        return;
    };
    if *value.kind() != NodeKind::StringLiteral {
        return;
    }
    let text = value
        .text()
        .trim_matches(|c| c == '\'' || c == '"' || c == '`');
    for token in text.split_whitespace() {
        if TEXT_CLASS_PREFIXES.iter().any(|p| token.starts_with(p)) && token.contains("px]") {
            out.push(Finding::new(
                format!(
                    "`{token}` sizes text in `px`; use a relative unit (`text-[Nrem]` or a Tailwind scale class like `text-sm`) so it scales with the user's font-size accessibility setting"
                ),
                attr.span(),
            ));
        }
    }
}

pub struct CssAbsoluteTextUnitRule {
    id: RuleId,
}

impl CssAbsoluteTextUnitRule {
    pub fn new() -> Self {
        Self {
            id: RuleId::new("react:css-absolute-text-unit").expect("valid rule id"),
        }
    }
}

impl Default for CssAbsoluteTextUnitRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for CssAbsoluteTextUnitRule {
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
            description: "Text sizing (`fontSize`, `lineHeight`, Tailwind `text-[...]`/`leading-[...]`) uses an absolute `px` value; use a relative unit instead so it scales with the user's font-size accessibility setting.".into(),
            tags: vec!["react".into(), "css".into(), "accessibility".into()],
            cwe: None,
            produces_hotspots: false,
        }
    }

    fn check(&self, file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        if vord_rules_engine::is_test_only_path(file.path()) {
            return Vec::new();
        }
        let mut findings = Vec::new();
        for el in ast.descendants().filter(|n| is_jsx_kind(n)) {
            flag_inline_style(el, &mut findings);
            flag_class_list(el, &mut findings);
        }
        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vord_rules_engine::AstParser;

    fn check(code: &str) -> Vec<Finding> {
        let file = SourceFile::new("t.tsx", code, LanguageIdentifier::typescript()).unwrap();
        let ast = vord_parser_typescript::TypeScriptParser::new()
            .parse(&file)
            .unwrap();
        CssAbsoluteTextUnitRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_inline_font_size_in_px() {
        let findings = check("const el = <div style={{ fontSize: '14px' }} />;\n");
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("fontSize"));
    }

    #[test]
    fn flags_inline_line_height_in_px() {
        let findings = check("const el = <div style={{ lineHeight: '20px' }} />;\n");
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn flags_tailwind_arbitrary_text_size() {
        let findings = check("const el = <p className=\"text-[14px]\">x</p>;\n");
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("text-[14px]"));
    }

    #[test]
    fn flags_tailwind_arbitrary_leading() {
        let findings = check("const el = <p className=\"leading-[20px]\">x</p>;\n");
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn allows_rem_font_size() {
        let findings = check("const el = <div style={{ fontSize: '1rem' }} />;\n");
        assert!(findings.is_empty());
    }

    #[test]
    fn allows_tailwind_scale_class() {
        let findings = check("const el = <p className=\"text-sm\">x</p>;\n");
        assert!(findings.is_empty());
    }

    #[test]
    fn allows_px_for_non_text_properties() {
        let findings =
            check("const el = <div style={{ width: '14px' }} className=\"p-[4px]\" />;\n");
        assert!(findings.is_empty());
    }
}
