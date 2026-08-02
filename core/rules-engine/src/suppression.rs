//! `// vord-ignore` suppression comments: an escape hatch for the rare line
//! a rule flags but a human has judged is fine — a detection regex that
//! legitimately contains a credential-shaped substring, a magic-byte
//! constant that trips the entropy heuristic, and so on.
//!
//! `// vord-ignore` alone (no colon) suppresses every rule on that line.
//! `// vord-ignore: rule-id[, rule-id...]` suppresses only the listed
//! rule(s) — anything after the first token of each comma-separated entry
//! is free-form human explanation, not part of the rule-id list.

/// True when `content`'s `line` (1-based) carries a `vord-ignore` comment
/// that covers `rule_id`.
pub fn is_suppressed(content: &str, line: u32, rule_id: &str) -> bool {
    let Some(index) = line.checked_sub(1) else {
        return false;
    };
    let Some(text) = content.lines().nth(index as usize) else {
        return false;
    };
    let Some(marker) = text.find("vord-ignore") else {
        return false;
    };

    let after = &text[marker + "vord-ignore".len()..];
    let Some(rest) = after.trim_start().strip_prefix(':') else {
        // Bare `// vord-ignore` with no colon: suppresses everything.
        return after.trim_start().is_empty()
            || !after
                .trim_start()
                .starts_with(|c: char| c.is_alphanumeric());
    };

    rest.split(',')
        .any(|entry| entry.split_whitespace().next() == Some(rule_id))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bare_ignore_suppresses_any_rule() {
        let content = "let x = 1; // vord-ignore\n";
        assert!(is_suppressed(content, 1, "secrets:high-entropy-string"));
        assert!(is_suppressed(content, 1, "smells:unwrap-usage"));
    }

    #[test]
    fn scoped_ignore_only_suppresses_listed_rules() {
        let content = "let x = 1; // vord-ignore: secrets:high-entropy-string\n";
        assert!(is_suppressed(content, 1, "secrets:high-entropy-string"));
        assert!(!is_suppressed(content, 1, "smells:unwrap-usage"));
    }

    #[test]
    fn scoped_ignore_accepts_a_comma_separated_list() {
        let content = "let x = 1; // vord-ignore: rule-a, rule-b\n";
        assert!(is_suppressed(content, 1, "rule-a"));
        assert!(is_suppressed(content, 1, "rule-b"));
        assert!(!is_suppressed(content, 1, "rule-c"));
    }

    #[test]
    fn explanatory_prose_after_the_rule_id_does_not_break_matching() {
        let content = "let h = \"X-Request-Id\"; // vord-ignore: secrets:high-entropy-string (this is the header name, not a secret)\n";
        assert!(is_suppressed(content, 1, "secrets:high-entropy-string"));
        assert!(!is_suppressed(content, 1, "smells:unwrap-usage"));
    }

    #[test]
    fn no_comment_present_is_not_suppressed() {
        assert!(!is_suppressed("let x = 1;\n", 1, "smells:unwrap-usage"));
    }

    #[test]
    fn out_of_range_line_is_not_suppressed() {
        assert!(!is_suppressed("let x = 1;\n", 99, "smells:unwrap-usage"));
    }
}
