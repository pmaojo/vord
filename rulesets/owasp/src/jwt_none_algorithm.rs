//! Rule: flags JWT code that sets the algorithm to the literal string
//! `"none"`/`'none'` — the classic `alg:none` signature-bypass
//! vulnerability, where a token with no signature is accepted as valid.
//! Deliberately does not match Python's `None` object (`algorithm=None`),
//! only the quoted string literal.

use regex::Regex;
use std::sync::LazyLock;
use vord_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile, Span};
use vord_rules_engine::{Finding, IssueType, Rule, RuleId, RuleMetadata, Severity};

/// Matches `alg`/`algorithm` (as a key or kwarg) assigned/mapped to the
/// quoted string `"none"`/`'none'` (case-insensitive on the value only —
/// JWT's `alg` header is conventionally lowercase but implementations vary).
static JWT_NONE_ALGORITHM: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)\balgorithm[s]?['"]?\s*[:=]\s*\[?\s*["']none["']|"alg"\s*:\s*["']none["']"#)
        .expect("valid regex")
});

pub struct JwtNoneAlgorithmRule {
    id: RuleId,
}

impl JwtNoneAlgorithmRule {
    pub fn new() -> Self {
        Self {
            id: RuleId::new("owasp:jwt-uses-none-algorithm").expect("valid rule id"),
        }
    }
}

impl Default for JwtNoneAlgorithmRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for JwtNoneAlgorithmRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn applies_to(&self, _language: &LanguageIdentifier) -> bool {
        true
    }

    fn default_severity(&self) -> Severity {
        Severity::Blocker
    }

    fn issue_type(&self) -> IssueType {
        IssueType::Vulnerability
    }

    fn metadata(&self) -> RuleMetadata {
        RuleMetadata {
            description: "JWT algorithm is set to the literal \"none\", disabling signature verification entirely. A token with `alg: none` and no signature is then accepted as valid — the classic JWT algorithm-confusion / signature-bypass vulnerability.".into(),
            tags: vec!["security".into(), "owasp-a02".into(), "jwt".into()],
            cwe: Some(347),
            produces_hotspots: false,
        }
    }

    fn check(&self, file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        if *ast.kind() != NodeKind::SourceUnit {
            return Vec::new();
        }

        let mut findings = Vec::new();
        for (idx, line) in file.content().lines().enumerate() {
            let trimmed = line.trim_start();
            if trimmed.starts_with("//") || trimmed.starts_with('#') || trimmed.starts_with('*') {
                continue;
            }
            if JWT_NONE_ALGORITHM.is_match(line) {
                let line_no = (idx + 1) as u32;
                findings.push(Finding::new(
                    "JWT algorithm set to the literal \"none\", disabling signature verification; a forged unsigned token would be accepted",
                    Span::new(line_no, 1, line_no, line.len().max(1) as u32),
                ));
            }
        }
        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check(path: &str, lang: LanguageIdentifier, code: &str) -> Vec<Finding> {
        let file = SourceFile::new(path, code, lang).unwrap();
        let ast = AstNode::new(
            NodeKind::SourceUnit,
            Span::new(1, 1, 1, code.len().max(1) as u32),
            code,
            vec![],
        );
        JwtNoneAlgorithmRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_double_quoted_none_algorithm() {
        let code = "const token = jwt.sign(payload, '', { algorithm: \"none\" });\n";
        assert_eq!(
            check("app.ts", LanguageIdentifier::typescript(), code).len(),
            1
        );
    }

    #[test]
    fn flags_single_quoted_none_algorithm() {
        let code = "jwt.decode(token, options={'algorithms': ['none']})\n";
        assert_eq!(check("app.py", LanguageIdentifier::python(), code).len(), 1);
    }

    #[test]
    fn flags_json_alg_header_none() {
        let code = "header := `{\"alg\": \"none\", \"typ\": \"JWT\"}`\n";
        assert_eq!(check("main.go", LanguageIdentifier::go(), code).len(), 1);
    }

    #[test]
    fn ignores_python_none_object_as_algorithm() {
        let code = "decode(token, key, algorithm=None)\n";
        assert!(check("app.py", LanguageIdentifier::python(), code).is_empty());
    }

    #[test]
    fn ignores_real_algorithm() {
        let code = "const token = jwt.sign(payload, secret, { algorithm: \"HS256\" });\n";
        assert!(check("app.ts", LanguageIdentifier::typescript(), code).is_empty());
    }
}
