//! Rule: flags hardcoded secret keys passed to JWT sign or verify calls.

use vord_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use vord_rules_engine::{Finding, IssueType, Rule, RuleId, RuleMetadata, Severity};

fn has_quoted_secret_arg(line: &str) -> bool {
    let bytes = line.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b',' {
            let mut j = i + 1;
            while j < bytes.len() && (bytes[j] == b' ' || bytes[j] == b'\t') {
                j += 1;
            }
            if j < bytes.len() && (bytes[j] == b'"' || bytes[j] == b'\'') {
                let quote = bytes[j];
                let mut k = j + 1;
                while k < bytes.len() && bytes[k] != quote {
                    k += 1;
                }
                if k < bytes.len() {
                    let literal = &line[j + 1..k];
                    let upper_lit = literal.to_uppercase();
                    if upper_lit != "HS256"
                        && upper_lit != "HS384"
                        && upper_lit != "HS512"
                        && upper_lit != "RS256"
                        && upper_lit != "RS384"
                        && upper_lit != "RS512"
                        && upper_lit != "NONE"
                    {
                        return true;
                    }
                }
            }
        }
        i += 1;
    }
    false
}

fn is_hardcoded_jwt_secret(line: &str) -> bool {
    let lower = line.to_lowercase();
    let has_jwt_call = lower.contains("jwt.sign(")
        || lower.contains("jwt.verify(")
        || lower.contains("jwt.encode(")
        || lower.contains("jwt.decode(")
        || lower.contains("jwt_sign(")
        || lower.contains("jwt_verify(");

    if !has_jwt_call {
        return false;
    }

    has_quoted_secret_arg(line)
}

pub struct HardcodedJwtSecretRule {
    id: RuleId,
}

impl HardcodedJwtSecretRule {
    pub fn new() -> Self {
        Self {
            id: RuleId::new("owasp:hardcoded-jwt-secret").expect("valid rule id"),
        }
    }
}

impl Default for HardcodedJwtSecretRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for HardcodedJwtSecretRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn applies_to(&self, _language: &LanguageIdentifier) -> bool {
        true
    }

    fn default_severity(&self) -> Severity {
        Severity::Critical
    }

    fn issue_type(&self) -> IssueType {
        IssueType::Vulnerability
    }

    fn metadata(&self) -> RuleMetadata {
        RuleMetadata {
            description: "Hardcoded secret keys used for JWT signing or verification expose the application to token forgery and authentication bypass. Secrets must be loaded securely from environment variables or configuration.".into(),
            tags: vec!["security".into(), "owasp-a07".into(), "jwt".into(), "secrets".into()],
            cwe: Some(798),
            produces_hotspots: false,
        }
    }

    fn check(&self, file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        if ast.kind() != &NodeKind::SourceUnit {
            return Vec::new();
        }
        if vord_rules_engine::is_test_only_path(file.path()) {
            return Vec::new();
        }
        let test_ranges = vord_rules_engine::rust_test_module_ranges(file.content());

        let mut findings = Vec::new();
        let content = file.content();

        for (idx, line) in content.lines().enumerate() {
            let line_no = (idx + 1) as u32;
            if vord_rules_engine::in_ranges(&test_ranges, line_no) {
                continue;
            }
            let trimmed = line.trim();
            if trimmed.starts_with("//") || trimmed.starts_with('#') || trimmed.starts_with('*') {
                continue;
            }

            if is_hardcoded_jwt_secret(line) {
                findings.push(Finding::new(
                    "Hardcoded secret key passed to JWT sign/verify function; load secrets from secure environment variables instead",
                    vord_ast::Span::new(line_no, 1, line_no, line.len().max(1) as u32),
                ));
            }
        }

        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_hardcoded_jwt_sign_secret() {
        let code = "const token = jwt.sign(payload, \"secret123\");\n";
        let file = SourceFile::new("app.js", code, LanguageIdentifier::typescript()).unwrap();
        let ast = AstNode::new(
            NodeKind::SourceUnit,
            vord_ast::Span::new(1, 1, 1, code.len() as u32),
            code,
            vec![],
        );
        let rule = HardcodedJwtSecretRule::new();
        let findings = rule.check(&file, &ast);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn flags_hardcoded_jwt_verify_secret() {
        let code = "const decoded = jwt.verify(token, 'secret123');\n";
        let file = SourceFile::new("app.js", code, LanguageIdentifier::typescript()).unwrap();
        let ast = AstNode::new(
            NodeKind::SourceUnit,
            vord_ast::Span::new(1, 1, 1, code.len() as u32),
            code,
            vec![],
        );
        let rule = HardcodedJwtSecretRule::new();
        let findings = rule.check(&file, &ast);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn allows_env_variable_jwt_secret() {
        let code = "const token = jwt.sign(payload, process.env.JWT_SECRET);\n";
        let file = SourceFile::new("app.js", code, LanguageIdentifier::typescript()).unwrap();
        let ast = AstNode::new(
            NodeKind::SourceUnit,
            vord_ast::Span::new(1, 1, 1, code.len() as u32),
            code,
            vec![],
        );
        let rule = HardcodedJwtSecretRule::new();
        let findings = rule.check(&file, &ast);
        assert!(findings.is_empty());
    }

    #[test]
    fn ignores_comments() {
        let code = "// jwt.sign(payload, \"secret123\")\n";
        let file = SourceFile::new("app.js", code, LanguageIdentifier::typescript()).unwrap();
        let ast = AstNode::new(
            NodeKind::SourceUnit,
            vord_ast::Span::new(1, 1, 1, code.len() as u32),
            code,
            vec![],
        );
        let rule = HardcodedJwtSecretRule::new();
        let findings = rule.check(&file, &ast);
        assert!(findings.is_empty());
    }
}
