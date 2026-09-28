use vord_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use vord_rules_engine::{Finding, IssueType, Rule, RuleId, Severity};

fn is_plain_pub(node: &AstNode) -> bool {
    node.text()
        .trim_start()
        .strip_prefix("pub")
        .is_some_and(|rest| rest.starts_with(|c: char| c.is_whitespace()))
}

fn signature_text(node: &AstNode) -> &str {
    let text = node.text();
    text.find('{').map(|i| &text[..i]).unwrap_or(text)
}

/// The index of the `>` matching the `<` at `s[open_idx]`, tracking only
/// angle-bracket depth (adequate for generic argument lists; fn-pointer
/// parens inside a generic arg don't themselves contain unbalanced `<`/`>`
/// in realistic signatures).
fn matching_close_angle(s: &str, open_idx: usize) -> Option<usize> {
    let bytes = s.as_bytes();
    let mut depth = 0i32;
    for (i, &b) in bytes.iter().enumerate().skip(open_idx) {
        match b as char {
            '<' => depth += 1,
            '>' => {
                depth -= 1;
                if depth == 0 {
                    return Some(i);
                }
            }
            _ => {}
        }
    }
    None
}

/// Splits `s` on top-level commas, treating `<`, `(`, `[` as depth-opening
/// and `>`, `)`, `]` as depth-closing so a nested generic or fn-pointer
/// type's own commas don't split an argument in two.
fn top_level_split(s: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut depth = 0i32;
    let mut start = 0usize;
    for (i, c) in s.char_indices() {
        match c {
            '<' | '(' | '[' => depth += 1,
            '>' | ')' | ']' => depth -= 1,
            ',' if depth == 0 => {
                parts.push(s[start..i].trim());
                start = i + c.len_utf8();
            }
            _ => {}
        }
    }
    let last = s[start..].trim();
    if !last.is_empty() {
        parts.push(last);
    }
    parts
}

/// Whether `err_type` is a "stringly typed" error — `String` or a `&str`
/// (with any lifetime) — rather than a real error type callers can match
/// on.
fn is_stringly_typed(err_type: &str) -> bool {
    let t = err_type.trim();
    t == "String" || (t.starts_with('&') && t.trim_start_matches('&').trim_start().ends_with("str"))
}

/// The error type of a `pub fn`'s `-> Result<_, E>` return type, if it
/// returns a `Result` at all.
fn result_error_type(fn_node: &AstNode) -> Option<&str> {
    let sig = signature_text(fn_node);
    let arrow = sig.rfind("->")?;
    let ret = &sig[arrow + 2..];
    let result_at = ret.find("Result<")?;
    let open = result_at + "Result".len();
    let close = matching_close_angle(ret, open)?;
    let inner = &ret[open + 1..close];
    let args = top_level_split(inner);
    args.get(1).copied()
}

/// A `pub fn` returning `Result<_, String>` or `Result<_, &str>` forces
/// every caller to match on (or, worse, parse) the error's text instead of
/// a real error type — losing the ability to distinguish failure modes
/// programmatically, and creating a mismatch with any sibling public
/// function in the same API that *does* return a proper error enum. Define
/// (or reuse) a proper error type instead.
pub struct InconsistentErrorTypeRule {
    id: RuleId,
}

impl InconsistentErrorTypeRule {
    pub fn new() -> Self {
        Self {
            id: RuleId::new("rust:inconsistent-error-type").expect("valid rule id"),
        }
    }
}

impl Default for InconsistentErrorTypeRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for InconsistentErrorTypeRule {
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
        20
    }

    fn metadata(&self) -> vord_rules_engine::RuleMetadata {
        vord_rules_engine::RuleMetadata {
            description: "A public function returning `Result<_, String>` or `Result<_, &str>` \
                forces every caller to match on error text instead of a real error type. \
                Define a proper error type so callers can distinguish failure modes \
                programmatically."
                .into(),
            tags: vec!["error-handling".into(), "api-design".into(), "rust".into()],
            cwe: None,
            produces_hotspots: false,
        }
    }

    fn check(&self, file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        let test_ranges = vord_rules_engine::rust_test_module_ranges(file.content());

        ast.descendants()
            .filter(|n| *n.kind() == NodeKind::FunctionDef)
            .filter(|n| is_plain_pub(n))
            .filter(|n| !vord_rules_engine::in_ranges(&test_ranges, n.span().start_line))
            .filter_map(|n| {
                let err_type = result_error_type(n)?;
                is_stringly_typed(err_type).then(|| {
                    Finding::new(
                        format!(
                            "this public function returns `Result<_, {}>`; a stringly typed \
                            error forces callers to match on text instead of a real error \
                            type",
                            err_type.trim()
                        ),
                        n.span(),
                    )
                })
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
        InconsistentErrorTypeRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_pub_fn_returning_result_string_error() {
        let findings = check("pub fn parse(s: &str) -> Result<i32, String> { Ok(1) }\n");
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn flags_pub_fn_returning_result_str_error() {
        let findings = check("pub fn parse(s: &str) -> Result<i32, &'static str> { Ok(1) }\n");
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn ignores_pub_fn_returning_result_with_custom_error_type() {
        assert!(check("pub fn parse(s: &str) -> Result<i32, ParseError> { Ok(1) }\n").is_empty());
    }

    #[test]
    fn ignores_pub_fn_returning_result_with_nested_generic_error_type() {
        assert!(
            check("pub fn parse(s: &str) -> Result<i32, Box<dyn std::error::Error>> { Ok(1) }\n")
                .is_empty()
        );
    }

    #[test]
    fn ignores_non_pub_fn_with_string_error() {
        assert!(check("fn parse(s: &str) -> Result<i32, String> { Ok(1) }\n").is_empty());
    }

    #[test]
    fn ignores_pub_fn_not_returning_result() {
        assert!(check("pub fn add(a: i32, b: i32) -> i32 { a + b }\n").is_empty());
    }

    #[test]
    fn ignores_inconsistent_error_type_inside_a_cfg_test_module() {
        let code = "fn prod() {}\n\n#[cfg(test)]\nmod tests {\n    pub fn parse(s: &str) -> Result<i32, String> { Ok(1) }\n}\n";
        assert!(check(code).is_empty());
    }
}
