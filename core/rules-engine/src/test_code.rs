//! Helpers for rules that want to exempt test code from detection: an
//! integration-test file (`tests/*.rs`, by Rust convention) is exempted
//! entirely, while a `#[cfg(test)] mod tests { ... }` block inside an
//! ordinary source file is exempted only for the lines inside it — the
//! surrounding production code in the same file still gets checked.

/// True when `path` has a `tests` path segment — the Rust convention for a
/// standalone integration-test crate, where a long/complex/secret-looking
/// line is far more likely to be an assertion-heavy test fixture than real
/// production code.
pub fn is_test_only_path(path: &str) -> bool {
    let lower = path.to_lowercase();
    if lower.contains(".spec.")
        || lower.contains(".test.")
        || lower.contains("__tests__")
        || lower.contains("/tests/")
        || lower.starts_with("tests/")
    {
        return true;
    }
    std::path::Path::new(path)
        .components()
        .any(|c| c.as_os_str() == "tests" || c.as_os_str() == "__tests__" || c.as_os_str() == "fixtures")
}

/// A half-open `[start, end)` line range (1-based, matching `Span`).
pub type LineRange = (u32, u32);

/// True when `line` falls inside any of `ranges`.
pub fn in_ranges(ranges: &[LineRange], line: u32) -> bool {
    ranges
        .iter()
        .any(|&(start, end)| line >= start && line < end)
}

/// Finds every `#[cfg(test)] mod ... { ... }` block in `content` and returns
/// each one's line range, brace-matched from the `mod`'s opening `{` to its
/// closing `{`. Brace-counting skips over the contents of string literals
/// (plain and raw) so a test fixture containing an intentionally unbalanced
/// brace inside a string doesn't truncate the range early.
pub fn rust_test_module_ranges(content: &str) -> Vec<LineRange> {
    let mut ranges = Vec::new();
    let bytes = content.as_bytes();
    let mut search_from = 0;

    while let Some(rel_idx) = content[search_from..].find("#[cfg(test)]") {
        let marker_idx = search_from + rel_idx;
        let Some(open_brace) = content[marker_idx..].find('{').map(|i| marker_idx + i) else {
            break;
        };
        let Some(close_brace) = match_brace(bytes, open_brace) else {
            break;
        };
        let start_line = 1 + content[..open_brace].matches('\n').count() as u32;
        let end_line = 1 + content[..close_brace].matches('\n').count() as u32 + 1;
        ranges.push((start_line, end_line));
        search_from = close_brace + 1;
    }

    ranges
}

/// If `bytes[i]` starts a string, raw string, or char literal, returns the
/// index just past it (its contents skipped as opaque). `None` if `i` isn't
/// the start of one of those (including a lifetime apostrophe, which looks
/// like a char literal but never closes).
fn skip_opaque_span(bytes: &[u8], i: usize) -> Option<usize> {
    match bytes[i] {
        b'"' => Some(skip_string(bytes, i)),
        b'r' if matches!(bytes.get(i + 1), Some(b'"') | Some(b'#')) => skip_raw_string(bytes, i),
        b'\'' => skip_char_literal(bytes, i),
        _ => None,
    }
}

/// Given the byte index of an opening `{`, finds the index of its matching
/// closing `}`, treating the contents of string/raw-string/char literals as
/// opaque (never counting braces inside them — see [`skip_opaque_span`]).
fn match_brace(bytes: &[u8], open_idx: usize) -> Option<usize> {
    let mut depth: i32 = 0;
    let mut i = open_idx;
    while i < bytes.len() {
        if let Some(next) = skip_opaque_span(bytes, i) {
            i = next;
            continue;
        }
        match bytes[i] {
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(i);
                }
            }
            _ => {}
        }
        i += 1;
    }
    None
}

/// Skips over a plain `"..."` string literal (with `\`-escape awareness)
/// starting at the opening quote; returns the index just past the closing
/// quote.
fn skip_string(bytes: &[u8], quote_idx: usize) -> usize {
    let mut i = quote_idx + 1;
    while i < bytes.len() {
        match bytes[i] {
            b'\\' => i += 2,
            b'"' => return i + 1,
            _ => i += 1,
        }
    }
    i
}

/// If `quote_idx` is the start of a char literal (`'x'`, `'\n'`,
/// `'\u{7b}'`), returns the index just past its closing `'`. Returns `None`
/// for a lifetime apostrophe (`'a`), which never closes.
fn skip_char_literal(bytes: &[u8], quote_idx: usize) -> Option<usize> {
    let mut i = quote_idx + 1;
    if bytes.get(i) == Some(&b'\\') {
        i += 1;
        if bytes.get(i) == Some(&b'u') && bytes.get(i + 1) == Some(&b'{') {
            i += 2;
            while bytes.get(i).is_some_and(|&b| b != b'}') {
                i += 1;
            }
            i += 1;
        } else {
            i += 1;
        }
    } else {
        i += 1;
    }
    (bytes.get(i) == Some(&b'\'')).then_some(i + 1)
}

/// Skips over a raw string literal (`r"..."`, `r#"..."#`, ...) starting at
/// the `r`; returns the index just past the closing delimiter, or `None` if
/// `i` isn't actually the start of a raw string.
fn skip_raw_string(bytes: &[u8], r_idx: usize) -> Option<usize> {
    let mut i = r_idx + 1;
    let mut hashes = 0;
    while bytes.get(i) == Some(&b'#') {
        hashes += 1;
        i += 1;
    }
    if bytes.get(i) != Some(&b'"') {
        return None;
    }
    i += 1;
    loop {
        let quote = bytes[i..].iter().position(|&b| b == b'"')?;
        let candidate = i + quote;
        let closes = bytes[candidate + 1..]
            .iter()
            .take(hashes)
            .all(|&b| b == b'#');
        if closes {
            return Some(candidate + 1 + hashes);
        }
        i = candidate + 1;
    }
}

/// True when `path` looks like vendored, third-party, or precompiled code
/// that should be excluded from static analysis to avoid false positives.
pub fn is_vendored_path(path: &str) -> bool {
    let lower = path.to_lowercase();

    // Minified / precompiled bundles
    if lower.ends_with(".min.js")
        || lower.ends_with(".min.css")
        || lower.ends_with(".bundle.js")
    {
        return true;
    }

    // Well-known vendored / build-output directories
    let vendored_segments: &[&str] = &[
        "/vendor/",
        "/vendors/",
        "/node_modules/",
        "/bower_components/",
        "/dist/",
        "/build/",
        "/third_party/",
        "/third-party/",
        "/3rdparty/",
        "/public/assets/",
        "/public/external/",
        "/public/demo/",
    ];

    // Normalise so that a relative path like `vendor/foo.js` is also caught
    // by prefixing a `/` when the path doesn't already start with one.
    let normalised = if lower.starts_with('/') {
        lower.clone()
    } else {
        format!("/{lower}")
    };

    vendored_segments
        .iter()
        .any(|seg| normalised.contains(seg))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_paths_under_a_tests_directory() {
        assert!(is_test_only_path("tests/e2e.rs"));
        assert!(is_test_only_path("core/rules-engine/tests/fixtures.rs"));
        assert!(!is_test_only_path("core/rules-engine/src/lib.rs"));
    }

    #[test]
    fn finds_a_simple_cfg_test_module_range() {
        let content = "fn prod() {}\n\n#[cfg(test)]\nmod tests {\n    fn one() {}\n}\n";
        let ranges = rust_test_module_ranges(content);
        assert_eq!(ranges.len(), 1);
        let (start, end) = ranges[0];
        assert!(in_ranges(&ranges, start));
        assert!(!in_ranges(&ranges, end));
        assert!(!in_ranges(&ranges, 1));
    }

    #[test]
    fn unbalanced_brace_inside_a_string_literal_does_not_truncate_the_range() {
        let content = "\
#[cfg(test)]
mod tests {
    #[test]
    fn handler_fixture() {
        let code = \"fn handler() {\";
        assert!(code.contains('{'));
    }

    #[test]
    fn second_test_still_inside_the_module() {
        assert!(true);
    }
}
";
        let ranges = rust_test_module_ranges(content);
        assert_eq!(ranges.len(), 1);
        let last_line = content.lines().count() as u32;
        assert!(in_ranges(&ranges, last_line - 1));
    }

    #[test]
    fn raw_string_with_a_brace_does_not_confuse_the_counter() {
        let content = "\
#[cfg(test)]
mod tests {
    const FIXTURE: &str = r#\"{ \"unterminated\": true \"#;

    #[test]
    fn still_inside() {
        assert!(true);
    }
}
";
        let ranges = rust_test_module_ranges(content);
        assert_eq!(ranges.len(), 1);
        let last_line = content.lines().count() as u32;
        assert!(in_ranges(&ranges, last_line - 1));
    }

    #[test]
    fn vendored_paths_are_detected() {
        // Minified files
        assert!(is_vendored_path("assets/jquery.min.js"));
        assert!(is_vendored_path("css/styles.min.css"));
        assert!(is_vendored_path("js/app.bundle.js"));

        // Well-known vendored directories
        assert!(is_vendored_path("vendor/gems/foo.rb"));
        assert!(is_vendored_path("vendors/lib/bar.js"));
        assert!(is_vendored_path("node_modules/lodash/index.js"));
        assert!(is_vendored_path("bower_components/angular/angular.js"));
        assert!(is_vendored_path("dist/bundle.js"));
        assert!(is_vendored_path("build/output.js"));
        assert!(is_vendored_path("third_party/protobuf/gen.rs"));
        assert!(is_vendored_path("third-party/lib.js"));
        assert!(is_vendored_path("3rdparty/utils.js"));

        // Rails / public patterns
        assert!(is_vendored_path("public/assets/application.js"));
        assert!(is_vendored_path("public/external/lib.js"));
        assert!(is_vendored_path("public/demo/sample.js"));

        // Case-insensitive
        assert!(is_vendored_path("NODE_MODULES/react/index.js"));
        assert!(is_vendored_path("Vendor/Lib/foo.php"));
    }

    #[test]
    fn normal_app_paths_are_not_vendored() {
        assert!(!is_vendored_path("src/main.rs"));
        assert!(!is_vendored_path("app/controllers/users.rb"));
        assert!(!is_vendored_path("lib/utils.ts"));
        assert!(!is_vendored_path("core/rules-engine/src/lib.rs"));
        assert!(!is_vendored_path("components/Button.tsx"));
    }
}
