//! Rule: flags a hardcoded hex color — an inline `style={{ color: '#...' }}`
//! (or `background`/`backgroundColor`/`border*`/`fill`/`stroke`), or a
//! Tailwind arbitrary-value color class (`bg-[#73747d]`, `text-[#fff]`,
//! `border-[#000]`). Review feedback on this codebase repeatedly asked
//! authors to check for a Tailwind palette token before reaching for a raw
//! hex value (`ObservationsSection`, `ProposalHeader`) — a design-system
//! color that happens to share a hex value with an ad hoc one silently
//! drifts apart the moment the palette changes.

use vord_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use vord_rules_engine::{Finding, IssueType, Rule, RuleId, RuleMetadata, Severity};

use crate::common::{attribute_value, find_attribute, is_jsx_kind, is_other, jsx_expression_inner};

const COLOR_STYLE_PROPS: [&str; 6] = [
    "color",
    "background",
    "backgroundColor",
    "borderColor",
    "fill",
    "stroke",
];
const COLOR_CLASS_PREFIXES: [&str; 7] = [
    "bg-[#",
    "text-[#",
    "border-[#",
    "fill-[#",
    "stroke-[#",
    "ring-[#",
    "shadow-[#",
];

fn is_hex_literal(text: &str) -> bool {
    let t = text.trim_matches(|c| c == '\'' || c == '"' || c == '`');
    t.starts_with('#')
        && matches!(t.len(), 4 | 5 | 7 | 9)
        && t[1..].chars().all(|c| c.is_ascii_hexdigit())
}

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
        if !COLOR_STYLE_PROPS.contains(&key.text()) {
            continue;
        }
        if *val.kind() == NodeKind::StringLiteral && is_hex_literal(val.text()) {
            out.push(Finding::new(
                format!(
                    "`{}: {}` hardcodes a hex color; check for an equivalent Tailwind/design-token color before inlining a raw hex value",
                    key.text(),
                    val.text()
                ),
                pair.span(),
            ));
        }
    }
}

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
        let Some(prefix) = COLOR_CLASS_PREFIXES.iter().find(|p| token.starts_with(**p)) else {
            continue;
        };
        let hex_part = &token[prefix.len() - 1..];
        if hex_part.ends_with(']') && is_hex_literal(&hex_part[..hex_part.len() - 1]) {
            out.push(Finding::new(
                format!(
                    "`{token}` hardcodes a hex color; check for an equivalent Tailwind palette class before inlining a raw hex value"
                ),
                attr.span(),
            ));
        }
    }
}

pub struct CssHardcodedHexColorRule {
    id: RuleId,
}

impl CssHardcodedHexColorRule {
    pub fn new() -> Self {
        Self {
            id: RuleId::new("react:css-hardcoded-hex-color").expect("valid rule id"),
        }
    }
}

impl Default for CssHardcodedHexColorRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for CssHardcodedHexColorRule {
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
            description: "A hex color literal is hardcoded inline (style prop or Tailwind arbitrary value) instead of using the project's Tailwind/design-token palette.".into(),
            tags: vec!["react".into(), "css".into(), "consistency".into()],
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
        CssHardcodedHexColorRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_inline_style_hex_color() {
        let findings = check("const el = <div style={{ color: '#73747d' }} />;\n");
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn flags_short_hex_form() {
        let findings = check("const el = <div style={{ backgroundColor: '#fff' }} />;\n");
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn flags_tailwind_arbitrary_hex_class() {
        let findings = check("const el = <div className=\"bg-[#73747d]\">x</div>;\n");
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("bg-[#73747d]"));
    }

    #[test]
    fn allows_tailwind_palette_class() {
        let findings = check("const el = <div className=\"bg-slate-500\">x</div>;\n");
        assert!(findings.is_empty());
    }

    #[test]
    fn allows_non_color_style_props() {
        let findings = check("const el = <div style={{ width: '10px' }} />;\n");
        assert!(findings.is_empty());
    }

    #[test]
    fn allows_css_variable_reference() {
        let findings = check("const el = <div style={{ color: 'var(--brand)' }} />;\n");
        assert!(findings.is_empty());
    }
}
