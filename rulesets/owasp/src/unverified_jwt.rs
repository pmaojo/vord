use vord_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use vord_rules_engine::{Finding, IssueType, Rule, RuleId, Severity};

pub struct UnverifiedJwtRule {
    id: RuleId,
}

impl UnverifiedJwtRule {
    pub fn new() -> Self {
        Self {
            id: RuleId::new("owasp:unverified-jwt").expect("valid rule id"),
        }
    }
}

impl Default for UnverifiedJwtRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for UnverifiedJwtRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn applies_to(&self, language: &LanguageIdentifier) -> bool {
        *language == LanguageIdentifier::typescript() || *language == LanguageIdentifier::python()
    }

    fn default_severity(&self) -> Severity {
        Severity::Critical
    }

    fn issue_type(&self) -> IssueType {
        IssueType::Vulnerability
    }

    fn metadata(&self) -> vord_rules_engine::RuleMetadata {
        vord_rules_engine::RuleMetadata {
            description: "Decoding or verifying a JWT with signature verification disabled (or using the 'none' algorithm) allows attackers to bypass authentication and forge tokens.".into(),
            tags: vec!["security".into(), "owasp-a07".into(), "cwe".into(), "jwt".into()],
            cwe: Some(287), // Improper Authentication
            produces_hotspots: false,
        }
    }

    fn check(&self, file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        if vord_rules_engine::is_test_only_path(file.path()) {
            return Vec::new();
        }

        let content = file.content();
        if !content.contains("jwt") {
            return Vec::new();
        }

        let mut findings = Vec::new();

        let is_python = *file.language() == LanguageIdentifier::python();
        let is_ts = *file.language() == LanguageIdentifier::typescript();

        for call in ast.descendants().filter(|n| *n.kind() == NodeKind::Call) {
            let Some(callee) = call.first_child() else {
                continue;
            };

            let callee_text = callee.text();
            if !callee_text.ends_with("jwt.decode") && !callee_text.ends_with("jwt.verify") {
                continue;
            }

            let call_text = call
                .text()
                .replace(" ", "")
                .replace("\n", "")
                .replace("\r", "");

            let mut is_vulnerable = false;

            if is_python
                && (call_text.contains("verify=False")
                    || call_text.contains("verify=false")
                    || call_text.contains("verify_signature") && call_text.contains("False")
                    || call_text.contains("algorithms=[\"none\"]")
                    || call_text.contains("algorithms=['none']")) // vord-ignore: owasp:jwt-uses-none-algorithm — detection pattern, not a live JWT config
            {
                is_vulnerable = true;
            }

            if is_ts
                && (call_text.contains("algorithms:[\"none\"]")
                    || call_text.contains("algorithms:['none']")) // vord-ignore: owasp:jwt-uses-none-algorithm — detection pattern, not a live JWT config
            {
                is_vulnerable = true;
            }

            if is_vulnerable {
                findings.push(Finding::new(
                    "Decoding a JWT with signature verification disabled or allowing the 'none' algorithm allows forging tokens.",
                    call.span(),
                ));
            }
        }

        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vord_rules_engine::AstParser;

    fn check(code: &str, lang: LanguageIdentifier) -> Vec<Finding> {
        let file = SourceFile::new("app.test", code, lang.clone()).unwrap();
        let ast = if lang == LanguageIdentifier::python() {
            vord_parser_python::PythonParser::new()
                .parse(&file)
                .unwrap()
        } else {
            vord_parser_typescript::TypeScriptParser::new()
                .parse(&file)
                .unwrap()
        };
        UnverifiedJwtRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_python_verify_false() {
        let code = "token = jwt.decode(encoded, verify=False)\n";
        assert_eq!(check(code, LanguageIdentifier::python()).len(), 1);
    }

    #[test]
    fn flags_python_verify_signature_false() {
        let code = "token = jwt.decode(encoded, options={\"verify_signature\": False})\n";
        assert_eq!(check(code, LanguageIdentifier::python()).len(), 1);
    }

    #[test]
    fn flags_typescript_none_algorithm() {
        let code = "jwt.verify(token, key, { algorithms: ['none'] });\n";
        assert_eq!(check(code, LanguageIdentifier::typescript()).len(), 1);
    }

    #[test]
    fn allows_safe_jwt_verification() {
        let code = "token = jwt.decode(encoded, key, algorithms=[\"HS256\"])\n";
        assert!(check(code, LanguageIdentifier::python()).is_empty());
    }

    #[test]
    fn flags_multiline_options() {
        let code =
            "token = jwt.decode(\n    encoded,\n    options={\"verify_signature\": False}\n)\n";
        assert_eq!(check(code, LanguageIdentifier::python()).len(), 1);
    }

    #[test]
    fn ignores_unrelated_verify_false() {
        let code = "requests.get(url, verify=False)\n";
        assert!(check(code, LanguageIdentifier::python()).is_empty());
    }
}
