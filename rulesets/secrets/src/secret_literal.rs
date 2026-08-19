//! Shared "secret-shaped literal assigned to a credential-named identifier"
//! heuristic used by the context-sensitive secrets rules (test fixtures,
//! config examples, documentation snippets). Kept in one place so all three
//! agree on what counts as a credential keyword, what counts as an obvious
//! placeholder, and what counts as "looks like a real secret".

use regex::{Captures, Regex};
use std::sync::LazyLock;

use crate::entropy::shannon_entropy;

/// Extracts the matched credential value from a [`CREDENTIAL_ASSIGNMENT`]
/// capture — group 2 for a quoted value, group 3 for a bare/unquoted one
/// (as in unquoted `.env` files).
pub fn assignment_value<'a>(caps: &'a Captures<'a>) -> &'a str {
    caps.get(2)
        .or_else(|| caps.get(3))
        .map(|m| m.as_str())
        .unwrap_or_default()
}

/// Matches `<credential-keyword-ish identifier> <:=> <value>`, where value
/// is either a quoted string or a bare token (as in unquoted `.env` files:
/// `API_TOKEN=abc123...`) — the same keyword vocabulary as the other
/// secrets rules (password, secret, token, api_key/apikey, credential,
/// private_key, access_key).
pub static CREDENTIAL_ASSIGNMENT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?i)\b\w*(password|passwd|secret|token|api[_-]?key|apikey|credential|private[_-]?key|access[_-]?key)\w*\s*[:=]\s*(?:["']([^"'\s]{8,})["']|([^\s"'#;,]{8,}))"#,
    )
    .expect("valid regex")
});

/// Obvious placeholder values that should never be flagged as real secrets,
/// even though they sit in a credential-named assignment.
const PLACEHOLDER_MARKERS: &[&str] = &[
    "your_api_key",
    "your-api-key",
    "youapikey",
    "yourapikey",
    "your_token",
    "your-token",
    "yourtoken",
    "your_password",
    "your-password",
    "yourpassword",
    "your_secret",
    "your-secret",
    "yoursecret",
    "xxx",
    "changeme",
    "change_me",
    "change-me",
    "example",
    "sample",
    "placeholder",
    "replace_me",
    "replaceme",
    "replace-me",
    "insert_key_here",
    "insert-key-here",
    "insertkeyhere",
    "todo",
    "fixme",
    "dummy",
    "fake",
    "test123",
    "none",
    "null",
    "redacted",
    "<token>",
    "<key>",
    "<secret>",
    "<password>",
];

/// True when `value` reads as an obvious placeholder rather than a real
/// credential: angle-bracket/`<...>` templates, all-repeated characters, or
/// one of the well-known placeholder words/phrases.
pub fn is_placeholder_value(value: &str) -> bool {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return true;
    }
    if trimmed.starts_with('<') && trimmed.ends_with('>') {
        return true;
    }
    if trimmed.starts_with('{') && trimmed.ends_with('}') {
        return true;
    }
    if trimmed.starts_with('$') {
        // Environment variable reference, e.g. `${API_KEY}` / `$API_KEY`.
        return true;
    }
    let lower = trimmed.to_lowercase();
    if PLACEHOLDER_MARKERS.iter().any(|m| lower.contains(m)) {
        return true;
    }
    // A run of a single repeated character (`xxxxxxxxxxxxxxxx`) or digit
    // sequence like `0000000000000000` carries no entropy and is plainly a
    // placeholder, not a real credential.
    if trimmed.chars().all(|c| c == trimmed.chars().next().unwrap()) {
        return true;
    }
    false
}

/// True when `value` looks like a real, non-placeholder secret: reasonable
/// length, mixed alphanumeric charset, and either high Shannon entropy or a
/// mix of letters and digits (catches structured-but-real keys like
/// `sk_live_...` that a strict entropy threshold alone might miss).
pub fn looks_like_real_secret(value: &str) -> bool {
    if value.len() < 12 || is_placeholder_value(value) {
        return false;
    }
    if !value.chars().all(|c| c.is_ascii() && !c.is_whitespace()) {
        return false;
    }
    let has_letter = value.chars().any(|c| c.is_ascii_alphabetic());
    let has_digit = value.chars().any(|c| c.is_ascii_digit());
    if !has_letter {
        return false;
    }
    shannon_entropy(value) >= 3.0 || (has_letter && has_digit && value.len() >= 16)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognizes_placeholders() {
        for v in [
            "YOUR_API_KEY",
            "<TOKEN>",
            "xxxxxxxxxxxxxxxx",
            "changeme",
            "example",
            "replace_me",
            "insert_key_here",
            "${API_KEY}",
        ] {
            assert!(is_placeholder_value(v), "expected placeholder: {v}");
        }
    }

    #[test]
    fn recognizes_real_secrets() {
        let stripe_shaped = ["sk_live_4eC39", "HqLyjW", "Darj", "tT1zdp", "7dc"].concat();
        assert!(looks_like_real_secret(&stripe_shaped));
        assert!(looks_like_real_secret(concat!(
            "aG3n7Zq9Lm2XpW5v",
            "Bt8FhKc1RdSy"
        )));
    }

    #[test]
    fn rejects_placeholders_as_real_secrets() {
        assert!(!looks_like_real_secret("YOUR_API_KEY"));
        assert!(!looks_like_real_secret("changeme"));
    }
}
