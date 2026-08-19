use vord_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use vord_rules_engine::{Finding, IssueType, Rule, RuleId, Severity};

/// Macros whose first (or, for the `write!` family, second) argument is
/// interpreted as a format string by the compiler.
fn format_macro_name(callee_text: &str) -> Option<&'static str> {
    let name = callee_text.trim_end_matches('!');
    let name = name.rsplit("::").next().unwrap_or(name);
    match name {
        "format" => Some("format!"),
        "print" => Some("print!"),
        "println" => Some("println!"),
        "eprint" => Some("eprint!"),
        "eprintln" => Some("eprintln!"),
        "write" => Some("write!"),
        "writeln" => Some("writeln!"),
        _ => None,
    }
}

/// Splits `s` (the text strictly inside a macro's parentheses) into its
/// top-level, comma-separated arguments, respecting nested
/// `(`/`[`/`{`/string-literal boundaries so a comma inside a nested call or
/// string doesn't split an argument in two.
fn top_level_args(s: &str) -> Vec<&str> {
    let mut args = Vec::new();
    let mut depth = 0i32;
    let mut in_string = false;
    let mut start = 0usize;
    let bytes = s.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        let c = bytes[i] as char;
        if in_string {
            if c == '\\' {
                i += 1; // skip the escaped character
            } else if c == '"' {
                in_string = false;
            }
        } else {
            match c {
                '"' => in_string = true,
                '(' | '[' | '{' => depth += 1,
                ')' | ']' | '}' => depth -= 1,
                ',' if depth == 0 => {
                    args.push(s[start..i].trim());
                    start = i + 1;
                }
                _ => {}
            }
        }
        i += 1;
    }
    let last = s[start..].trim();
    if !last.is_empty() || !args.is_empty() {
        args.push(last);
    }
    args
}

fn is_string_literal(arg: &str) -> bool {
    let arg = arg.trim();
    arg.starts_with('"') || arg.starts_with("r\"") || arg.starts_with("r#")
}

/// The macro argument holding the format string, if any: the first
/// argument for `format!`/`print!`/..., the second for `write!`/`writeln!`
/// (whose first argument is the writer, not the format string).
fn format_string_arg<'a>(macro_name: &str, args: &[&'a str]) -> Option<&'a str> {
    match macro_name {
        "write!" | "writeln!" => args.get(1).copied(),
        _ => args.first().copied(),
    }
}

/// A `format!`/`println!`/`write!`-family macro whose format-string
/// argument is not a string literal — i.e. it's a variable or expression
/// being used as the format string. `format_args!`'s mini-language is
/// evaluated at the call site by the compiler when the literal is known at
/// compile time; passing a runtime-constructed string instead defeats that
/// checking and, if any part of the string comes from untrusted input, is
/// the classic format-string injection shape.
pub struct FormatStringRuntimeConstructedRule {
    id: RuleId,
}

impl FormatStringRuntimeConstructedRule {
    pub fn new() -> Self {
        Self {
            id: RuleId::new("rust:format-string-runtime-constructed").expect("valid rule id"),
        }
    }
}

impl Default for FormatStringRuntimeConstructedRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for FormatStringRuntimeConstructedRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn applies_to(&self, language: &LanguageIdentifier) -> bool {
        *language == LanguageIdentifier::rust()
    }

    fn default_severity(&self) -> Severity {
        Severity::Major
    }

    fn issue_type(&self) -> IssueType {
        IssueType::CodeSmell
    }

    fn remediation_effort_minutes(&self) -> u32 {
        10
    }

    fn metadata(&self) -> vord_rules_engine::RuleMetadata {
        vord_rules_engine::RuleMetadata {
            description: "`format!`/`println!`/`write!`-family macros expect a string \
                *literal* as their format string, checked at compile time. Passing a \
                variable or expression instead skips that checking and, if it ever contains \
                untrusted input, opens the door to format-string injection."
                .into(),
            tags: vec!["security".into(), "rust".into()],
            cwe: Some(134),
            produces_hotspots: false,
        }
    }

    fn check(&self, file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        let test_ranges = vord_rules_engine::rust_test_module_ranges(file.content());

        ast.descendants()
            .filter(|n| *n.kind() == NodeKind::Call)
            .filter(|n| !vord_rules_engine::in_ranges(&test_ranges, n.span().start_line))
            .filter_map(|call| {
                let callee = call.first_child()?;
                let macro_name = format_macro_name(callee.text())?;
                let text = call.text();
                let open = text.find('(')?;
                let close = text.rfind(')')?;
                if close <= open {
                    return None;
                }
                // A macro invocation (`write!(..)`) always carries a `!`
                // between the callee path and the opening paren. A plain
                // function/method call that merely shares a macro's name —
                // `std::fs::write(path, data)`, `File::write(buf)`, the
                // `Write` trait's `.write(buf)` — has no `!` there, and its
                // arguments (e.g. file contents) are not a format string.
                if !text[..open].contains('!') {
                    return None;
                }
                let args = top_level_args(&text[open + 1..close]);
                let fmt_arg = format_string_arg(macro_name, &args)?;
                if fmt_arg.is_empty() || is_string_literal(fmt_arg) {
                    return None;
                }
                Some(Finding::new(
                    format!(
                        "`{macro_name}`'s format string is not a literal (`{fmt_arg}`); a \
                        runtime-constructed format string skips compile-time checking and \
                        risks format-string injection if it can contain untrusted input"
                    ),
                    call.span(),
                ))
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
        FormatStringRuntimeConstructedRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_format_with_variable_fmt_string() {
        let findings = check("fn f(msg: &str) { let _ = format!(msg); }\n");
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn flags_println_with_variable_fmt_string() {
        let findings = check("fn f(msg: String) { println!(msg); }\n");
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn flags_write_with_non_literal_second_argument() {
        let findings = check("fn f(w: &mut String, msg: &str) { write!(w, msg).unwrap(); }\n");
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn ignores_format_with_literal_fmt_string() {
        assert!(check("fn f(x: i32) { let _ = format!(\"x = {}\", x); }\n").is_empty());
    }

    #[test]
    fn ignores_write_with_literal_second_argument() {
        assert!(
            check("fn f(w: &mut String) { write!(w, \"hello {}\", 1).unwrap(); }\n").is_empty()
        );
    }

    #[test]
    fn ignores_raw_string_literal_fmt_string() {
        assert!(check("fn f() { let _ = format!(r\"literal {}\", 1); }\n").is_empty());
    }

    #[test]
    fn ignores_unrelated_macro() {
        assert!(check("fn f(v: Vec<i32>) { let _ = vec![v]; }\n").is_empty());
    }

    #[test]
    fn ignores_std_fs_write_which_only_shares_the_macro_name() {
        // `std::fs::write(path, contents)` is a plain two-argument function,
        // not the `write!` macro — its second argument is file contents,
        // not a format string, and must not be flagged.
        let findings = check(
            "fn f(path: &std::path::Path, raw: String) -> std::io::Result<()> {\n    std::fs::write(path, raw)\n}\n",
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn ignores_write_trait_method_call_which_only_shares_the_macro_name() {
        // `writer.write(buf)` (the `std::io::Write`/`Write` trait method) is
        // a method call, not the `write!` macro invocation.
        let findings = check(
            "fn f(w: &mut dyn std::io::Write, buf: &[u8]) -> std::io::Result<usize> {\n    w.write(buf)\n}\n",
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn ignores_format_string_runtime_constructed_inside_a_cfg_test_module() {
        let code = "fn prod() {}\n\n#[cfg(test)]\nmod tests {\n    #[test]\n    fn t(msg: &str) {\n        let _ = format!(msg);\n    }\n}\n";
        assert!(check(code).is_empty());
    }
}
