//! Rule: flags the specific, actually-dangerous CORS misconfiguration —
//! an unrestricted/reflected origin *combined with* credentials enabled.
//! Distinct from `owasp:permissive-cors`, which flags a wildcard/`true`
//! origin alone (a nuisance, but browsers reject `Access-Control-Allow-
//! Origin: *` together with credentialed requests) — this rule targets the
//! combination that browsers *do* allow and that actually exposes
//! authenticated endpoints to any origin: origin reflection/wildcard plus
//! `Access-Control-Allow-Credentials: true` / `credentials: true` /
//! `credentials: 'include'`.

use regex::Regex;
use std::sync::LazyLock;
use vord_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile, Span};
use vord_rules_engine::{Finding, IssueType, Rule, RuleId, RuleMetadata, Severity};

/// An unrestricted or reflected CORS origin: a wildcard `*`, `origin: true`,
/// or reflecting the request's own `Origin` header back verbatim (a common
/// bypass for the "credentials forbids wildcard" browser rule).
static UNRESTRICTED_ORIGIN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?i)(access-control-allow-origin[^=:,]*[=:,]\s*['"]?\*['"]?|origin\s*:\s*true|origin\s*:\s*['"]\*['"]|(access-control-allow-origin[^;\n]*|corsheaders_allow_all_origins\s*=\s*true|cors_origin_allow_all\s*=\s*true)[^;\n]*\b(req|request)\.headers|\bheaders\s*\[['"]origin['"]\]|\bheaders\.get\s*\(\s*['"]origin['"]\s*\))"#,
    )
    .expect("valid regex")
});

/// Credentials explicitly enabled on the CORS response/config.
static CREDENTIALS_ENABLED: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?i)(access-control-allow-credentials[^=:,]*[=:,]\s*['"]?true['"]?|credentials\s*:\s*true|credentials\s*:\s*['"]include['"])"#,
    )
    .expect("valid regex")
});

pub struct CorsCredentialsRule {
    id: RuleId,
}

impl CorsCredentialsRule {
    pub fn new() -> Self {
        Self {
            id: RuleId::new("owasp:cors-all-origins-and-credentials").expect("valid rule id"),
        }
    }
}

impl Default for CorsCredentialsRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for CorsCredentialsRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn applies_to(&self, lang: &LanguageIdentifier) -> bool {
        *lang != LanguageIdentifier::rust()
    }

    fn default_severity(&self) -> Severity {
        Severity::Critical
    }

    fn issue_type(&self) -> IssueType {
        IssueType::Vulnerability
    }

    fn metadata(&self) -> RuleMetadata {
        RuleMetadata {
            description: "CORS is configured with an unrestricted or reflected origin AND credentials enabled together. Unlike a bare wildcard origin (which browsers reject for credentialed requests), reflecting the request's Origin header while allowing credentials lets any site make authenticated cross-origin requests on a logged-in user's behalf.".into(),
            tags: vec!["security".into(), "owasp-a05".into(), "cors".into()],
            cwe: Some(942),
            produces_hotspots: false,
        }
    }

    fn check(&self, file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        if *ast.kind() != NodeKind::SourceUnit {
            return Vec::new();
        }

        let content = file.content();
        // Scan with a small sliding window (current + next few lines) so a
        // config object spanning multiple lines — origin on one line,
        // credentials on the next — is still caught, while staying a cheap
        // line-based heuristic like the rest of this ruleset.
        const WINDOW: usize = 5;
        let lines: Vec<&str> = content.lines().collect();

        let mut findings = Vec::new();
        let mut flagged_lines = std::collections::HashSet::new();
        for (idx, line) in lines.iter().enumerate() {
            let trimmed = line.trim_start();
            if trimmed.starts_with("//") || trimmed.starts_with('#') || trimmed.starts_with('*') {
                continue;
            }
            if !UNRESTRICTED_ORIGIN.is_match(line) {
                continue;
            }
            let window_end = (idx + WINDOW).min(lines.len());
            let has_credentials = lines[idx..window_end]
                .iter()
                .any(|l| CREDENTIALS_ENABLED.is_match(l));
            if has_credentials {
                let line_no = (idx + 1) as u32;
                if flagged_lines.insert(line_no) {
                    findings.push(Finding::new(
                        "CORS allows an unrestricted/reflected origin together with credentials enabled; any site can then make authenticated cross-origin requests on a logged-in user's behalf",
                        Span::new(line_no, 1, line_no, line.len().max(1) as u32),
                    ));
                }
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
        CorsCredentialsRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_reflected_origin_with_credentials_true() {
        let code = "app.use(cors({\n  origin: true,\n  credentials: true,\n}));\n";
        assert_eq!(
            check("app.ts", LanguageIdentifier::typescript(), code).len(),
            1
        );
    }

    #[test]
    fn flags_wildcard_origin_header_with_allow_credentials_header() {
        let code = "res.setHeader('Access-Control-Allow-Origin', '*');\nres.setHeader('Access-Control-Allow-Credentials', 'true');\n";
        assert_eq!(
            check("app.ts", LanguageIdentifier::typescript(), code).len(),
            1
        );
    }

    #[test]
    fn flags_python_credentials_include_with_wildcard() {
        let code = "CORS_ORIGIN_ALLOW_ALL = True\nresp.headers['Access-Control-Allow-Origin'] = '*'\nresp.headers['Access-Control-Allow-Credentials'] = 'true'\n";
        assert_eq!(check("views.py", LanguageIdentifier::python(), code).len(), 1);
    }

    #[test]
    fn ignores_wildcard_origin_without_credentials() {
        let code = "res.setHeader('Access-Control-Allow-Origin', '*');\n";
        assert!(check("app.ts", LanguageIdentifier::typescript(), code).is_empty());
    }

    #[test]
    fn ignores_credentials_with_specific_origin() {
        let code = "app.use(cors({\n  origin: 'https://example.com',\n  credentials: true,\n}));\n";
        assert!(check("app.ts", LanguageIdentifier::typescript(), code).is_empty());
    }
}
