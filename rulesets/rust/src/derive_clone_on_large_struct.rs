use vord_ast::{AstNode, LanguageIdentifier, SourceFile};
use vord_rules_engine::{Finding, IssueType, Rule, RuleId, Severity};

use crate::common::is_other;

/// A struct with this many or more named fields is "large" enough that
/// `#[derive(Clone)]` risks becoming an expensive, easy-to-miss deep copy —
/// especially once fields grow to hold `String`/`Vec`/`HashMap`/nested
/// structs. Picked to flag genuinely wide aggregates while staying quiet on
/// the small structs (2-7 fields) that make up the bulk of ordinary code.
const LARGE_STRUCT_FIELD_THRESHOLD: usize = 10;

/// Whether the contiguous run of attribute (`#[...]`) and doc-comment
/// (`///`) lines directly above `start_line` (1-based) includes a
/// `derive(..)` attribute naming `Clone`. Stops at the first line that is
/// none of those, so an attribute documenting an earlier, different item
/// doesn't count for this one.
fn derives_clone_directly_above(lines: &[&str], start_line: u32) -> bool {
    let mut found = false;
    for line in lines[..start_line.saturating_sub(1) as usize].iter().rev() {
        let trimmed = line.trim();
        let is_attr_or_doc = trimmed.starts_with("#[") || trimmed.starts_with("///");
        if !is_attr_or_doc {
            break;
        }
        if trimmed.starts_with("#[") && trimmed.contains("derive") && trimmed.contains("Clone") {
            found = true;
        }
    }
    found
}

fn named_field_count(struct_item: &AstNode) -> Option<usize> {
    let fields = struct_item
        .children()
        .iter()
        .find(|c| is_other(c.kind(), "field_declaration_list"))?;
    Some(
        fields
            .children()
            .iter()
            .filter(|c| is_other(c.kind(), "field_declaration"))
            .count(),
    )
}

/// Deriving `Clone` on a wide struct silently signs up every call site for
/// an O(n) deep copy — cheap to write, easy to forget is there, and a
/// common source of unexpected allocation churn once the struct grows
/// `String`/`Vec`/nested fields. Not wrong by itself, but worth a second
/// look: consider `Arc<Inner>` for cheap sharing, or splitting the struct.
pub struct DeriveCloneOnLargeStructRule {
    id: RuleId,
}

impl DeriveCloneOnLargeStructRule {
    pub fn new() -> Self {
        Self {
            id: RuleId::new("rust:derive-clone-on-large-struct").expect("valid rule id"),
        }
    }
}

impl Default for DeriveCloneOnLargeStructRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for DeriveCloneOnLargeStructRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn applies_to(&self, language: &LanguageIdentifier) -> bool {
        *language == LanguageIdentifier::rust()
    }

    fn default_severity(&self) -> Severity {
        Severity::Minor
    }

    fn issue_type(&self) -> IssueType {
        IssueType::CodeSmell
    }

    fn remediation_effort_minutes(&self) -> u32 {
        15
    }

    fn metadata(&self) -> vord_rules_engine::RuleMetadata {
        vord_rules_engine::RuleMetadata {
            description: "`#[derive(Clone)]` on a struct with many fields signs up every call \
                site for a deep copy of all of them. Consider wrapping the data in `Arc` for \
                cheap sharing, or splitting the struct, instead of deriving `Clone` wholesale."
                .into(),
            tags: vec!["performance".into(), "rust".into()],
            cwe: None,
            produces_hotspots: false,
        }
    }

    fn check(&self, file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        let lines: Vec<&str> = file.content().lines().collect();
        let test_ranges = vord_rules_engine::rust_test_module_ranges(file.content());

        ast.descendants()
            .filter(|n| is_other(n.kind(), "struct_item"))
            .filter(|n| !vord_rules_engine::in_ranges(&test_ranges, n.span().start_line))
            .filter(|n| derives_clone_directly_above(&lines, n.span().start_line))
            .filter(|n| named_field_count(n).is_some_and(|c| c >= LARGE_STRUCT_FIELD_THRESHOLD))
            .map(|n| {
                Finding::new(
                    format!(
                        "this struct derives `Clone` with {} or more fields; a deep clone \
                        this wide is easy to trigger by accident — consider `Arc` for cheap \
                        sharing or splitting the struct",
                        LARGE_STRUCT_FIELD_THRESHOLD
                    ),
                    n.span(),
                )
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use vord_ast::SourceFile;
    use vord_rules_engine::AstParser;

    use super::*;

    fn check(code: &str) -> Vec<Finding> {
        let file = SourceFile::new("t.rs", code, LanguageIdentifier::rust()).unwrap();
        let ast = vord_parser_rust::RustParser::new().parse(&file).unwrap();
        DeriveCloneOnLargeStructRule::new().check(&file, &ast)
    }

    fn wide_struct(derive: &str) -> String {
        format!(
            "{derive}\nstruct Wide {{\n    a: String,\n    b: String,\n    c: String,\n    d: String,\n    e: String,\n    f: String,\n    g: String,\n    h: String,\n    i: String,\n    j: String,\n}}\n"
        )
    }

    #[test]
    fn flags_derive_clone_on_wide_struct() {
        let findings = check(&wide_struct("#[derive(Clone, Debug)]"));
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn ignores_wide_struct_without_clone_derive() {
        assert!(check(&wide_struct("#[derive(Debug)]")).is_empty());
    }

    #[test]
    fn ignores_small_struct_with_clone_derive() {
        let findings = check("#[derive(Clone)]\nstruct Small {\n    a: u32,\n    b: u32,\n}\n");
        assert!(findings.is_empty());
    }

    #[test]
    fn ignores_unrelated_attribute_above_struct() {
        let code = "#[derive(Clone)]\nstruct Other;\n\n#[derive(Debug)]\nstruct Wide {\n    a: String,\n    b: String,\n    c: String,\n    d: String,\n    e: String,\n    f: String,\n    g: String,\n    h: String,\n    i: String,\n    j: String,\n}\n";
        assert!(check(code).is_empty());
    }

    #[test]
    fn ignores_derive_clone_on_wide_struct_inside_a_cfg_test_module() {
        let code = format!(
            "fn prod() {{}}\n\n#[cfg(test)]\nmod tests {{\n{}\n}}\n",
            wide_struct("    #[derive(Clone)]")
        );
        assert!(check(&code).is_empty());
    }
}
