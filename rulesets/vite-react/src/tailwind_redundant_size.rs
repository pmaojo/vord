//! Rule: an `h-<n>` and a `w-<n>` Tailwind utility with the *same* value
//! sit side by side in a JSX `className`/`class` attribute — Tailwind 3.4
//! added `size-<n>` as a single utility for "square box", so writing both
//! axes out is pure redundancy (and a drift risk: editing one and
//! forgetting the other silently breaks the square).

use globset::GlobSet;
use vord_ast::{AstNode, LanguageIdentifier, SourceFile};
use vord_rules_engine::{Finding, IssueType, Rule, RuleId, RuleMetadata, Severity};

use crate::common::{
    build_globset, class_attribute_span, class_attribute_text, is_excepted, is_jsx_kind,
};

pub struct TailwindRedundantSizeRule {
    id: RuleId,
    exceptions: GlobSet,
}

impl TailwindRedundantSizeRule {
    pub fn new() -> Self {
        Self::with_exceptions(Vec::new())
    }

    pub fn with_exceptions(globs: Vec<String>) -> Self {
        Self {
            id: RuleId::new("vite-react:tailwind-redundant-size").expect("valid rule id"),
            exceptions: build_globset(&globs),
        }
    }
}

impl Default for TailwindRedundantSizeRule {
    fn default() -> Self {
        Self::new()
    }
}

/// `h-<n>`/`w-<n>` map to `size-<n>` only when `<n>` denotes the same
/// physical value on both axes — a bare numeric/fraction scale step, `px`,
/// `full`, `auto`, `fit`, `min`, `max`, or an arbitrary value in brackets.
/// Viewport-relative keywords (`screen`, `dvh`/`dvw`, ...) are deliberately
/// excluded: `h-screen` is `100vh` and `w-screen` is `100vw`, so the
/// suffixes matching is coincidence, not equivalence — there's no
/// `size-screen`. An arbitrary value is only trusted when the bracket
/// contents are byte-identical between the `h-` and `w-` tokens, which the
/// caller already enforces by comparing the two value strings outright.
fn is_size_compatible(value: &str) -> bool {
    if value.starts_with('[') && value.ends_with(']') {
        return true;
    }
    if matches!(value, "auto" | "px" | "full" | "fit" | "min" | "max") {
        return true;
    }
    if value.parse::<f64>().is_ok() {
        return true;
    }
    if let Some((numerator, denominator)) = value.split_once('/') {
        return numerator.parse::<f64>().is_ok() && denominator.parse::<f64>().is_ok();
    }
    false
}

/// Splits a token like `sm:hover:h-4` into its variant prefix
/// (`sm:hover:`, kept with the trailing colon, empty if there is none) and
/// its value (`4`) — only for tokens whose base utility is `h-`/`w-`.
fn variant_and_value<'a>(token: &'a str, utility: &str) -> Option<(&'a str, &'a str)> {
    if let Some(value) = token.strip_prefix(utility) {
        return Some(("", value));
    }
    let needle = format!(":{utility}");
    let idx = token.rfind(&needle)?;
    Some((&token[..=idx], &token[idx + needle.len()..]))
}

impl Rule for TailwindRedundantSizeRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn applies_to(&self, language: &LanguageIdentifier) -> bool {
        language.is_typescript() || language.is_javascript()
    }

    fn default_severity(&self) -> Severity {
        Severity::Minor
    }

    fn issue_type(&self) -> IssueType {
        IssueType::CodeSmell
    }

    fn metadata(&self) -> RuleMetadata {
        RuleMetadata {
            description: "An `h-<n>` and a `w-<n>` Tailwind utility with the same value sit in the same class list — use `size-<n>` instead, Tailwind's single utility for a square box.".into(),
            tags: vec!["vite-react".into(), "tailwind".into(), "css".into()],
            cwe: None,
            produces_hotspots: false,
        }
    }

    fn check(&self, file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        if vord_rules_engine::is_test_only_path(file.path())
            || is_excepted(file.path(), &self.exceptions)
        {
            return Vec::new();
        }
        ast.descendants()
            .filter(|n| is_jsx_kind(n))
            .filter_map(|el| {
                let text = class_attribute_text(el)?;
                let tokens: Vec<&str> = text.split_whitespace().collect();

                let mut heights: Vec<(&str, &str)> = Vec::new();
                let mut widths: Vec<(&str, &str)> = Vec::new();
                for token in &tokens {
                    if let Some(pair) = variant_and_value(token, "h-") {
                        heights.push(pair);
                    } else if let Some(pair) = variant_and_value(token, "w-") {
                        widths.push(pair);
                    }
                }

                let (variant, value) = heights.iter().find_map(|(h_variant, h_value)| {
                    widths
                        .iter()
                        .find(|(w_variant, w_value)| {
                            w_variant == h_variant && w_value == h_value
                        })
                        .filter(|_| is_size_compatible(h_value))
                        .map(|_| (*h_variant, *h_value))
                })?;

                let span = class_attribute_span(el).unwrap_or_else(|| el.span());
                Some(Finding::new(
                    format!(
                        "`{variant}h-{value}` and `{variant}w-{value}` in a class list — use `{variant}size-{value}` instead"
                    ),
                    span,
                ))
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vord_rules_engine::AstParser;

    fn tsx(code: &str) -> Vec<Finding> {
        let file = SourceFile::new(
            "src/components/Avatar.tsx",
            code,
            LanguageIdentifier::typescript(),
        )
        .unwrap();
        let ast = vord_parser_typescript::TypeScriptParser::new()
            .parse(&file)
            .unwrap();
        TailwindRedundantSizeRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_matching_h_and_w() {
        let findings = tsx("const el = <div className=\"h-2 w-2\">x</div>;\n");
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("size-2"));
    }

    #[test]
    fn flags_regardless_of_order_and_other_classes() {
        let findings =
            tsx("const el = <div className=\"flex w-8 rounded-full h-8 bg-gray-200\" />;\n");
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("size-8"));
    }

    #[test]
    fn flags_matching_arbitrary_values() {
        let findings = tsx("const el = <div className=\"h-[20px] w-[20px]\" />;\n");
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("size-[20px]"));
    }

    #[test]
    fn flags_with_a_shared_variant_prefix() {
        let findings = tsx("const el = <div className=\"sm:h-4 sm:w-4\" />;\n");
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("sm:size-4"));
    }

    #[test]
    fn silent_on_mismatched_values() {
        assert!(tsx("const el = <div className=\"h-2 w-4\" />;\n").is_empty());
    }

    #[test]
    fn silent_on_mismatched_variants() {
        assert!(tsx("const el = <div className=\"h-4 sm:w-4\" />;\n").is_empty());
    }

    #[test]
    fn silent_on_viewport_keywords() {
        assert!(tsx("const el = <div className=\"h-screen w-screen\" />;\n").is_empty());
    }

    #[test]
    fn silent_on_mismatched_arbitrary_values() {
        assert!(tsx("const el = <div className=\"h-[10vh] w-[10vw]\" />;\n").is_empty());
    }

    #[test]
    fn silent_with_no_class_attribute() {
        assert!(tsx("const el = <div>x</div>;\n").is_empty());
    }

    #[test]
    fn silent_on_a_dynamic_class_expression() {
        assert!(tsx("const el = <div className={styles.avatar}>x</div>;\n").is_empty());
    }
}
