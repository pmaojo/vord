//! Rule: flags `svh` used as a viewport-height unit — Tailwind arbitrary
//! values (`h-[100svh]`, `min-h-[50svh]`) or an inline `style` value
//! (`height: '100svh'`). Review feedback on `MessageList` flagged known
//! mobile-browser bugs with `svh`; `dvh` (dynamic viewport height) is the
//! unit that tracks the on-screen chrome correctly there.

use vord_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use vord_rules_engine::{Finding, IssueType, Rule, RuleId, RuleMetadata, Severity};

use crate::common::{attribute_value, find_attribute, is_jsx_kind, is_other, jsx_expression_inner};

fn mentions_svh(text: &str) -> bool {
    text.split(|c: char| !c.is_ascii_alphanumeric() && c != '.' && c != '%')
        .any(|tok| {
            tok.ends_with("svh")
                && tok[..tok.len() - 3]
                    .chars()
                    .next()
                    .is_some_and(|c| c.is_ascii_digit())
        })
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
        let [_, val] = pair.children() else { continue };
        if *val.kind() == NodeKind::StringLiteral && mentions_svh(val.text()) {
            out.push(Finding::new(
                "`svh` has known mobile-browser rendering bugs; prefer `dvh` for viewport-height layouts",
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
        if token.contains('[') && mentions_svh(token) {
            out.push(Finding::new(
                format!("`{token}` uses `svh`, which has known mobile-browser rendering bugs; prefer `dvh`"),
                attr.span(),
            ));
        }
    }
}

pub struct CssSvhViewportUnitRule {
    id: RuleId,
}

impl CssSvhViewportUnitRule {
    pub fn new() -> Self {
        Self {
            id: RuleId::new("react:css-svh-viewport-unit").expect("valid rule id"),
        }
    }
}

impl Default for CssSvhViewportUnitRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for CssSvhViewportUnitRule {
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
            description: "The `svh` viewport unit has known mobile-browser rendering bugs; prefer `dvh` for layouts that depend on mobile viewport height.".into(),
            tags: vec!["react".into(), "css".into(), "mobile".into()],
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
        CssSvhViewportUnitRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_tailwind_arbitrary_svh() {
        let findings = check("const el = <div className=\"h-[100svh]\">x</div>;\n");
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("h-[100svh]"));
    }

    #[test]
    fn flags_inline_style_svh() {
        let findings = check("const el = <div style={{ height: '100svh' }} />;\n");
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn allows_dvh() {
        let findings = check("const el = <div className=\"h-[100dvh]\">x</div>;\n");
        assert!(findings.is_empty());
    }

    #[test]
    fn allows_unrelated_classes() {
        let findings = check("const el = <div className=\"flex h-screen\">x</div>;\n");
        assert!(findings.is_empty());
    }
}
