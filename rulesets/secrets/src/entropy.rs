//! Shannon-entropy scoring for string literals that look like random
//! tokens/keys even when they don't match any known provider signature.
//! This is the generic net that catches private/self-hosted service tokens,
//! newly-issued provider formats we haven't special-cased yet, and one-off
//! random secrets.

use yunq_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use yunq_rules_engine::{Finding, IssueType, Rule, RuleId, RuleMetadata, Severity};

/// Shannon entropy of `s`, in bits per character, computed from the
/// character-frequency distribution within `s` itself (not a fixed
/// alphabet). Empty input has zero entropy.
pub fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let mut freq: std::collections::HashMap<char, u32> = std::collections::HashMap::new();
    let mut len: u32 = 0;
    for c in s.chars() {
        *freq.entry(c).or_insert(0) += 1;
        len += 1;
    }
    let len = f64::from(len);
    freq.values().fold(0.0, |acc, &count| {
        let p = f64::from(count) / len;
        acc - p * p.log2()
    })
}

/// Resolves the handful of common backslash escapes (`\n`, `\t`, `\r`,
/// `\\`, `\"`, `\'`, `\0`) to their actual character, leaving anything else
/// untouched. A literal like `"rule_id,severity,message\n"` reads as a
/// comma-joined header row followed by a real newline once unescaped —
/// exactly the shape the whitespace/charset checks below already know how
/// to recognize as non-secret — rather than a string ending in a stray `\`
/// symbol byte.
fn unescape_common(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.peek() {
            Some('n') => out.push('\n'),
            Some('t') => out.push('\t'),
            Some('r') => out.push('\r'),
            Some('0') => out.push('\0'),
            Some(&esc @ ('\\' | '"' | '\'')) => out.push(esc),
            _ => {
                out.push(c);
                continue;
            }
        }
        chars.next();
    }
    out
}

/// Strips one layer of matching quote characters (`"`, `'`, `` ` ``) so
/// entropy is computed over the literal's value, not its syntax.
fn strip_quotes(s: &str) -> &str {
    let bytes = s.as_bytes();
    if bytes.len() >= 2 {
        let first = bytes[0];
        let last = bytes[bytes.len() - 1];
        if first == last && matches!(first, b'"' | b'\'' | b'`') {
            return &s[1..s.len() - 1];
        }
    }
    s
}

/// Common hex digest lengths (MD5, SHA-1, SHA-224/256, SHA-384, SHA-512) —
/// high entropy but almost always a checksum or git commit SHA, not a
/// secret.
fn looks_like_hex_digest(s: &str) -> bool {
    s.len() >= 8
        && matches!(s.len(), 32 | 40 | 56 | 64 | 96 | 128)
        && s.chars().all(|c| c.is_ascii_hexdigit())
}

/// RFC 4122 UUID shape (`8-4-4-4-12` hex groups) — a common non-secret
/// identifier that happens to have high entropy.
fn looks_like_uuid(s: &str) -> bool {
    let expected_lengths = [8, 4, 4, 4, 12];
    let parts: Vec<&str> = s.split('-').collect();
    parts.len() == expected_lengths.len()
        && parts
            .iter()
            .zip(expected_lengths)
            .all(|(part, len)| part.len() == len && part.chars().all(|c| c.is_ascii_hexdigit()))
}

/// URLs, filesystem paths and Subresource-Integrity/lockfile hash prefixes:
/// all can be high-entropy but are not secrets.
fn looks_like_url_path_or_integrity_hash(s: &str) -> bool {
    const INTEGRITY_PREFIXES: &[&str] = &["sha1-", "sha256-", "sha384-", "sha512-"];
    s.contains("://")
        || s.starts_with("data:")
        || s.starts_with('/')
        || s.starts_with("./")
        || s.starts_with("../")
        || (s.contains('/') && s.contains('.'))
        // Two or more path separators is a strong path/route signal on its
        // own — `refs/heads/main`, `api/auth/oauth/github/callback` — even
        // without a literal `.` anywhere in the string.
        || s.matches('/').count() >= 2
        || s.starts_with("urn:")
        || INTEGRITY_PREFIXES.iter().any(|p| s.starts_with(p))
}

/// A Rust `format!`-style interpolation template — `{candidate}`,
/// `{public_url}/api/...`, `{}` — is source code building a string, not the
/// secret value that ends up in it.
fn looks_like_format_template(s: &str) -> bool {
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'{'
            && let Some(rel_close) = s[i + 1..].find('}')
        {
            let inner = &s[i + 1..i + 1 + rel_close];
            let is_placeholder = inner
                .chars()
                .all(|c| c.is_alphanumeric() || matches!(c, '_' | ':' | '.' | '?' | '#' | '<' | '>' | '^' | '+' | '-'));
            if is_placeholder {
                return true;
            }
            i += 1 + rel_close + 1;
            continue;
        }
        i += 1;
    }
    false
}

/// Real secrets/tokens are essentially always alphanumeric-plus-symbols
/// (base64, hex-with-mixed-context, or `prefix_base62...`); plain English
/// words and identifiers (camelCase, snake_case prose, kebab-case rule ids,
/// `namespace:name` pairs, dotted config keys) contain only letters plus
/// `_-:.,` structural punctuation. Requiring a digit or a symbol outside
/// that structural set filters most of that prose out while keeping actual
/// token shapes (base64 uses `+/=`, hex/base62 tokens carry digits, etc).
fn has_secret_like_charset(s: &str) -> bool {
    const STRUCTURAL: &[u8] = b"_-:.,";
    let has_digit = s.bytes().any(|b| b.is_ascii_digit());
    let has_symbol =
        s.bytes().any(|b| !b.is_ascii_alphanumeric() && !STRUCTURAL.contains(&b));
    has_digit || has_symbol
}

/// One `-`/`_`/`:`/`.`/`,`/`[`/`]`-separated piece of a longer string,
/// judged as "a word someone typed" rather than "a run of random bytes":
/// alphanumeric, short, and — when it carries digits — not also mixing
/// letter case. `missing`, `a11y`, `20250929` and `CamelCase` all pass;
/// `aG3n7Zq9Lm2XpW5` (mixed case *and* digits) and any run longer than a
/// plausible word do not.
fn is_word_like_segment(s: &str) -> bool {
    const MAX_WORD_LEN: usize = 15;
    if s.len() > MAX_WORD_LEN || !s.chars().all(|c| c.is_ascii_alphanumeric()) {
        return false;
    }
    let has_digit = s.bytes().any(|b| b.is_ascii_digit());
    let has_upper = s.bytes().any(|b| b.is_ascii_uppercase());
    let has_lower = s.bytes().any(|b| b.is_ascii_lowercase());
    !(has_digit && has_upper && has_lower)
}

/// A structured identifier — a rule id (`a11y:missing-lang-attribute`), a
/// model name (`claude-sonnet-4-5-20250929`), a dotted accessor path
/// (`.choices[0].message.content`) — rather than a secret.
///
/// [`has_secret_like_charset`] alone lets all three through, because each
/// contains a digit, and that is the only signal it asks for. What
/// actually separates them from a token is *segmentation*: an identifier
/// is several short words joined by structural punctuation, while a
/// random token is one unbroken run (or, for a prefixed key like
/// `sk-proj-<random>`, a couple of short words followed by a long run
/// that is not a word). So: two or more segments, every one of them
/// word-like.
fn looks_like_delimited_identifier(s: &str) -> bool {
    const DELIMITERS: &[char] = &['-', '_', ':', '.', ',', '[', ']'];
    let segments: Vec<&str> = s.split(DELIMITERS).filter(|part| !part.is_empty()).collect();
    segments.len() >= 2 && segments.iter().all(|part| is_word_like_segment(part))
}

/// Flags string literals whose Shannon entropy is high enough to look like
/// a random token/key, regardless of provider — the catch-all for
/// private/self-hosted services and formats without a dedicated pattern.
pub struct HighEntropyStringRule {
    id: RuleId,
    /// Minimum entropy, in bits per character, to flag.
    threshold: f64,
    /// Minimum literal length (post quote-stripping) to consider — short
    /// strings don't carry enough signal to score reliably.
    min_length: usize,
}

impl HighEntropyStringRule {
    pub fn new() -> Self {
        Self::with_threshold(3.5, 20)
    }

    /// Builds the rule with a custom threshold/minimum length, e.g. for a
    /// stricter or looser profile.
    pub fn with_threshold(threshold: f64, min_length: usize) -> Self {
        Self { id: RuleId::new("secrets:high-entropy-string").expect("valid rule id"), threshold, min_length }
    }
}

impl Default for HighEntropyStringRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for HighEntropyStringRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn applies_to(&self, _language: &LanguageIdentifier) -> bool {
        true
    }

    fn default_severity(&self) -> Severity {
        Severity::Major
    }

    fn issue_type(&self) -> IssueType {
        IssueType::Vulnerability
    }

    fn metadata(&self) -> RuleMetadata {
        RuleMetadata {
            description: "String literal has high Shannon entropy and looks like a random token/key rather than ordinary text. Catches unclassified and private/self-hosted service secrets that don't match a known provider format.".into(),
            tags: vec!["security".into(), "secrets".into(), "owasp-a07".into()],
            cwe: Some(798),
            produces_hotspots: false,
        }
    }

    fn check(&self, file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        if yunq_rules_engine::is_test_only_path(file.path()) {
            return Vec::new();
        }
        let test_ranges = yunq_rules_engine::rust_test_module_ranges(file.content());

        let mut findings = Vec::new();

        for literal in ast.descendants().filter(|n| *n.kind() == NodeKind::StringLiteral) {
            if yunq_rules_engine::in_ranges(&test_ranges, literal.span().start_line) {
                continue;
            }
            let value = unescape_common(strip_quotes(literal.text()));
            let value = value.as_str();

            if value.len() < self.min_length || value.contains(char::is_whitespace) {
                continue;
            }
            if looks_like_hex_digest(value)
                || looks_like_uuid(value)
                || looks_like_url_path_or_integrity_hash(value)
                || looks_like_format_template(value)
                || looks_like_delimited_identifier(value)
            {
                continue;
            }
            if !has_secret_like_charset(value) {
                continue;
            }

            let entropy = shannon_entropy(value);
            if entropy >= self.threshold {
                findings.push(Finding::new(
                    format!(
                        "string literal has high entropy ({entropy:.2} bits/char over {} chars) and looks like a random secret/token",
                        value.chars().count()
                    ),
                    literal.span(),
                ));
            }
        }

        findings
    }
}

#[cfg(test)]
mod tests {
    use yunq_ast::SourceFile;
    use yunq_rules_engine::AstParser;

    use super::*;

    fn check_ts(code: &str) -> Vec<Finding> {
        let file = SourceFile::new("t.ts", code, LanguageIdentifier::typescript()).unwrap();
        let ast = yunq_parser_typescript::TypeScriptParser::new().parse(&file).unwrap();
        HighEntropyStringRule::new().check(&file, &ast)
    }

    #[test]
    fn entropy_of_repeated_char_is_zero() {
        assert_eq!(shannon_entropy("aaaaaaaa"), 0.0);
    }

    #[test]
    fn entropy_of_empty_string_is_zero() {
        assert_eq!(shannon_entropy(""), 0.0);
    }

    #[test]
    fn flags_random_looking_token() {
        let code = "const apiToken = \"aG3n7Zq9Lm2XpW5vBt8FhKc1RdSy\";\n";
        let findings = check_ts(code);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn ignores_structured_identifiers_that_merely_contain_digits() {
        // The regression this guards: `has_secret_like_charset` accepts any
        // string containing a digit, so a rule id, a model name and a
        // dotted accessor path all cleared it and then scored above the
        // entropy threshold on character variety alone. All three are
        // source-code identifiers sitting in plain sight, not credentials.
        for identifier in [
            "a11y:missing-lang-attribute",
            "claude-sonnet-4-5-20250929",
            ".choices[0].message.content",
            "secrets:high-entropy-string",
            "text-embedding-3-small",
        ] {
            let code = format!("const x = \"{identifier}\";\n");
            assert!(check_ts(&code).is_empty(), "flagged identifier {identifier} as a secret");
        }
    }

    #[test]
    fn still_flags_a_prefixed_token_whose_random_half_is_not_word_like() {
        // The guard on the exemption above: a `prefix-prefix-<random>` key
        // is segmented too, but its payload segment is neither short nor
        // word-shaped, so it must still be caught.
        let code = "const k = \"sk-proj-aG3n7Zq9Lm2XpW5vBt8FhKc1RdSy\";\n";
        assert_eq!(check_ts(code).len(), 1);
    }

    #[test]
    fn ignores_short_strings() {
        assert!(check_ts("const x = \"aB3!\";\n").is_empty());
    }

    #[test]
    fn ignores_plain_english_sentence() {
        let code = "const msg = \"could not connect to the database, please retry\";\n";
        assert!(check_ts(code).is_empty());
    }

    #[test]
    fn ignores_common_identifier_style_text() {
        let code = "const description = \"aVeryDescriptiveHumanReadableConfigurationOptionName\";\n";
        assert!(check_ts(code).is_empty());
    }

    #[test]
    fn ignores_git_sha1_and_sha256() {
        let code = "const commit = \"a94a8fe5ccb19ba61c4c0873d391e987982fbbd3\";\n\
                    const digest = \"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\";\n";
        assert!(check_ts(code).is_empty());
    }

    #[test]
    fn ignores_uuid() {
        let code = "const requestId = \"550e8400-e29b-41d4-a716-446655440000\";\n";
        assert!(check_ts(code).is_empty());
    }

    #[test]
    fn ignores_urls_and_paths() {
        let code = "const url = \"https://example.com/some/very/long/descriptive/path\";\n\
                    const p = \"/usr/local/share/some-long-application-name/config\";\n";
        assert!(check_ts(code).is_empty());
    }

    #[test]
    fn ignores_subresource_integrity_hash() {
        let code = "const sri = \"sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxy9rx7HNQlGYl1kPzQho1wx4JwY8wC\";\n";
        assert!(check_ts(code).is_empty());
    }

    #[test]
    fn ignores_snake_case_identifier_style_text() {
        assert!(check_ts("const m = \"yunq_process_uptime_seconds\";\n").is_empty());
    }

    #[test]
    fn ignores_namespaced_kebab_case_rule_ids() {
        assert!(check_ts("const rule = \"owasp:hardcoded-secret\";\n").is_empty());
    }

    #[test]
    fn ignores_dotted_config_keys_and_comma_joined_lists() {
        assert!(check_ts("const key = \"analysis.exclusions.default\";\n").is_empty());
        assert!(check_ts("const list = \"read:user,user:email,repo:status\";\n").is_empty());
    }

    #[test]
    fn ignores_format_string_placeholders() {
        assert!(check_ts("const url = \"{public_url}/api/auth/oauth/github/callback\";\n").is_empty());
        assert!(check_ts("const metric = \"yunq_http_requests_total{{method=\\\"{}\\\",route=\\\"{}\\\"}}\";\n").is_empty());
    }

    #[test]
    fn ignores_comma_joined_header_row_with_trailing_newline_escape() {
        let code = "const h = \"rule_id,severity,file_path,start_line,message\\n\";\n";
        assert!(check_ts(code).is_empty());
    }

    #[test]
    fn ignores_urn_identifiers() {
        assert!(check_ts("const s = \"urn:ietf:params:scim:api:messages:2.0:ListResponse\";\n").is_empty());
    }

    #[test]
    fn ignores_extensionless_multi_segment_paths() {
        assert!(check_ts("const p = \"refs/remotes/origin/HEAD\";\n").is_empty());
        assert!(check_ts("const p2 = \"api/auth/oauth/github/callback\";\n").is_empty());
    }

    #[test]
    fn respects_custom_threshold() {
        let file = SourceFile::new(
            "t.ts",
            "const apiToken = \"aG3n7Zq9Lm2XpW5vBt8FhKc1RdSy\";\n",
            LanguageIdentifier::typescript(),
        )
        .unwrap();
        let ast = yunq_parser_typescript::TypeScriptParser::new().parse(&file).unwrap();
        let strict_rule = HighEntropyStringRule::with_threshold(5.9, 20);
        assert!(strict_rule.check(&file, &ast).is_empty());
    }
}
