//! Regex signatures for well-known cloud/SaaS credential formats. Each
//! provider gets its own rule id so profiles can activate/tune them
//! independently, but they all share one implementation: match a regex
//! against each line of the raw source. Line-based (not AST-based) matching
//! means these fire in any file type — `.env`, YAML/JSON configs, CI
//! manifests, README snippets — not only in string literals of a parsed
//! language, which matters for provider keys that leak outside source code.

use regex::Regex;
use yunq_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile, Span};
use yunq_rules_engine::{Finding, IssueType, Rule, RuleId, RuleMetadata, Severity};

/// One provider credential format: id, human description, and the regex
/// that recognizes it. Patterns are deliberately anchored with `\b`/length
/// bounds to avoid matching short prose that merely mentions a prefix.
struct ProviderSpec {
    id: &'static str,
    description: &'static str,
    pattern: &'static str,
}

const PROVIDER_SPECS: &[ProviderSpec] = &[
    ProviderSpec {
        id: "secrets:aws-access-key-id",
        description: "AWS access key id",
        pattern: r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b", // yunq-ignore (detection regex itself, not a secret)
    },
    ProviderSpec {
        id: "secrets:aws-secret-access-key",
        description: "AWS secret access key assigned to an `aws_secret_access_key`-named field",
        pattern: r#"(?i)aws_secret_access_key\s*[:=]\s*['"]?[A-Za-z0-9/+=]{40}['"]?"#, // yunq-ignore (detection regex itself, not a secret)
    },
    ProviderSpec {
        id: "secrets:gcp-api-key",
        description: "Google Cloud API key",
        pattern: r"\bAIza[0-9A-Za-z_\-]{35}\b", // yunq-ignore (detection regex itself, not a secret)
    },
    ProviderSpec {
        id: "secrets:gcp-service-account-key",
        description: "Google Cloud service account private key (JSON key file)",
        pattern: r#""private_key"\s*:\s*"-----BEGIN (RSA )?PRIVATE KEY"#, // yunq-ignore (detection regex itself, not a secret)
    },
    ProviderSpec {
        id: "secrets:azure-storage-connection-string",
        description: "Azure Storage account connection string account key",
        pattern: r"AccountKey=[A-Za-z0-9+/]{40,}={0,2}", // yunq-ignore (detection regex itself, not a secret)
    },
    ProviderSpec {
        id: "secrets:azure-sas-token",
        description: "Azure shared access signature (SAS) token",
        pattern: r"[?&]sv=\d{4}-\d{2}-\d{2}[^\s\x22\x27]*[?&]sig=[A-Za-z0-9%]{20,}", // yunq-ignore (detection regex itself, not a secret)
    },
    ProviderSpec {
        id: "secrets:stripe-live-key",
        description: "Stripe live secret/publishable/restricted key",
        pattern: r"\b(?:sk|pk|rk)_live_[0-9a-zA-Z]{24,}\b", // yunq-ignore (detection regex itself, not a secret)
    },
    ProviderSpec {
        id: "secrets:private-key-block",
        description: "PEM-encoded private key material",
        pattern: r"-----BEGIN ((RSA|EC|DSA|OPENSSH|PGP) )?PRIVATE KEY-----", // yunq-ignore (detection regex itself, not a secret)
    },
    ProviderSpec {
        id: "secrets:github-token",
        description: "GitHub personal access / OAuth / app / refresh token",
        pattern: r"\bgh[oprsu]_[A-Za-z0-9]{36,}\b|\bgithub_pat_[A-Za-z0-9_]{22,}\b", // yunq-ignore (detection regex itself, not a secret)
    },
    ProviderSpec {
        id: "secrets:slack-token",
        description: "Slack API token",
        pattern: r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b", // yunq-ignore (detection regex itself, not a secret)
    },
    ProviderSpec {
        id: "secrets:npm-token",
        description: "npm registry access token",
        pattern: r"\bnpm_[A-Za-z0-9]{36,}\b", // yunq-ignore (detection regex itself, not a secret)
    },
    ProviderSpec {
        id: "secrets:jwt-like-token",
        description: "JWT-shaped token (base64url header.payload.signature)",
        pattern: r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b", // yunq-ignore (detection regex itself, not a secret)
    },
];

/// A single provider-signature rule: a compiled regex checked against every
/// line of the file's raw content.
pub struct RegexSecretRule {
    id: RuleId,
    description: String,
    pattern: Regex,
}

impl RegexSecretRule {
    /// Builds a rule from an already-known-valid `(id, description, pattern)`
    /// triple. Used internally for the shipped provider specs, where the
    /// pattern is a compile-time constant.
    fn from_spec(spec: &ProviderSpec) -> Self {
        Self {
            id: RuleId::new(spec.id).expect("valid rule id"),
            description: spec.description.to_string(),
            pattern: Regex::new(spec.pattern).expect("valid built-in regex"),
        }
    }
}

impl Rule for RegexSecretRule {
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
            description: format!("Detects a hardcoded {}.", self.description),
            tags: vec!["security".into(), "secrets".into(), "owasp-a07".into()],
            cwe: Some(798),
            produces_hotspots: false,
        }
    }

    fn check(&self, file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        if *ast.kind() != NodeKind::SourceUnit {
            return Vec::new();
        }
        if yunq_rules_engine::is_test_only_path(file.path()) {
            return Vec::new();
        }
        let test_ranges = yunq_rules_engine::rust_test_module_ranges(file.content());

        let mut findings = Vec::new();
        for (idx, line) in file.content().lines().enumerate() {
            let line_no = (idx + 1) as u32;
            if yunq_rules_engine::in_ranges(&test_ranges, line_no) {
                continue;
            }
            if self.pattern.is_match(line) {
                findings.push(Finding::new(
                    format!("line looks like a hardcoded {}", self.description),
                    Span::new(line_no, 1, line_no, line.len().max(1) as u32),
                ));
            }
        }
        findings
    }
}

/// Every shipped provider-signature rule, one per credential format.
pub fn all_provider_rules() -> Vec<Box<dyn Rule>> {
    PROVIDER_SPECS
        .iter()
        .map(|spec| Box::new(RegexSecretRule::from_spec(spec)) as Box<dyn Rule>)
        .collect()
}

#[cfg(test)]
mod tests {
    use yunq_ast::SourceFile;
    use yunq_rules_engine::AstParser;

    use super::*;

    fn check_rule(id: &str, code: &str) -> Vec<Finding> {
        let spec = PROVIDER_SPECS
            .iter()
            .find(|s| s.id == id)
            .unwrap_or_else(|| panic!("no such spec: {id}"));
        let rule = RegexSecretRule::from_spec(spec);
        let file = SourceFile::new("t.ts", code, LanguageIdentifier::typescript()).unwrap();
        let ast = yunq_parser_typescript::TypeScriptParser::new()
            .parse(&file)
            .unwrap();
        rule.check(&file, &ast)
    }

    #[test]
    fn every_provider_spec_id_and_pattern_are_valid() {
        for spec in PROVIDER_SPECS {
            RuleId::new(spec.id).unwrap_or_else(|_| panic!("invalid rule id: {}", spec.id));
            Regex::new(spec.pattern).unwrap_or_else(|_| panic!("invalid regex for {}", spec.id));
        }
    }

    #[test]
    fn detects_aws_access_key_id() {
        let key = ["AKIAIOSFODNN7", "EXAMPLE"].concat();
        let findings = check_rule(
            "secrets:aws-access-key-id",
            &format!("const k = \"{key}\";\n"),
        );
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn ignores_aws_looking_but_short_string() {
        assert!(check_rule("secrets:aws-access-key-id", "const k = \"AKIA123\";\n").is_empty());
    }

    #[test]
    fn detects_aws_secret_access_key() {
        let secret = ["wJalrXUtnFEMI/K7MDENG/b", "PxRfiCYEXAMPLEKEY"].concat();
        let code = format!("aws_secret_access_key = \"{secret}\"\n");
        assert_eq!(check_rule("secrets:aws-secret-access-key", &code).len(), 1);
    }

    #[test]
    fn detects_gcp_api_key() {
        let key = ["AIzaSyD-9tSrke72PouQMnMX", "-a7eZSW0jkFMBWQ"].concat();
        let findings = check_rule("secrets:gcp-api-key", &format!("const k = \"{key}\";\n"));
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn ignores_gcp_prefix_in_prose() {
        assert!(check_rule("secrets:gcp-api-key", "// see AIza docs for details\n").is_empty());
    }

    #[test]
    fn detects_gcp_service_account_key() {
        let marker = [
            "-----BEGIN PRI",
            "VATE KEY-----\\nMII...\\n-----END PRIVATE KEY-----\\n",
        ]
        .concat();
        let code = format!("{{\"type\": \"service_account\", \"private_key\": \"{marker}\"}}\n");
        assert_eq!(
            check_rule("secrets:gcp-service-account-key", &code).len(),
            1
        );
    }

    #[test]
    fn detects_azure_storage_connection_string() {
        let account_key = [
            "Eby8vdM02xNOcqFlqUwJPLlm",
            "Eb26PoLNhH8Rh0P6Ohu8SIWXeghdI4WFHU=",
        ]
        .concat();
        let code = format!(
            "const conn = \"DefaultEndpointsProtocol=https;AccountName=foo;AccountKey={account_key};EndpointSuffix=core.windows.net\";\n"
        );
        assert_eq!(
            check_rule("secrets:azure-storage-connection-string", &code).len(),
            1
        );
    }

    #[test]
    fn detects_azure_sas_token() {
        let sig = ["A9x8zP3Qy7vLtR2wYbNcAeFgHjKl", "MnPqRsTuVwXyZ012345%3D"].concat();
        let code = format!(
            "const url = \"https://acct.blob.core.windows.net/c/f?sv=2020-08-04&ss=b&sig={sig}\";\n"
        );
        assert_eq!(check_rule("secrets:azure-sas-token", &code).len(), 1);
    }

    #[test]
    fn detects_stripe_live_keys() {
        let sk_live = ["sk_live_4eC39HqLyjWDarj", "tT1zdp7dc"].concat();
        assert_eq!(
            check_rule(
                "secrets:stripe-live-key",
                &format!("const k = \"{sk_live}\";\n")
            )
            .len(),
            1
        );
    }

    #[test]
    fn ignores_stripe_test_keys() {
        assert!(
            check_rule(
                "secrets:stripe-live-key",
                "const k = \"sk_test_4eC39HqLyjWDarjtT1zdp7dc\";\n"
            )
            .is_empty()
        );
    }

    #[test]
    fn detects_private_key_block() {
        let block = ["-----BEGIN RSA PRI", "VATE KEY-----"].concat();
        assert_eq!(
            check_rule("secrets:private-key-block", &format!("{block}\n")).len(),
            1
        );
    }

    #[test]
    fn detects_github_tokens() {
        let ghp = ["ghp_16C7e42F292c6912E77", "10c838347Ae178B4a"].concat();
        assert_eq!(
            check_rule("secrets:github-token", &format!("const t = \"{ghp}\";\n")).len(),
            1
        );
    }

    #[test]
    fn ignores_github_prefix_mentioned_in_docs() {
        assert!(
            check_rule("secrets:github-token", "// tokens start with ghp_ prefix\n").is_empty()
        );
    }

    #[test]
    fn detects_slack_token() {
        let xoxb = ["xoxb-2444333222111-sim", "ulated-token-value"].concat();
        assert_eq!(
            check_rule("secrets:slack-token", &format!("const t = \"{xoxb}\";\n")).len(),
            1
        );
    }

    #[test]
    fn detects_npm_token() {
        let token = ["npm_1234567890abcdefghij", "klmnopqrstuvwxyz1234"].concat();
        assert_eq!(
            check_rule(
                "secrets:npm-token",
                &format!(".npmrc: //registry.npmjs.org/:_authToken={token}\n")
            )
            .len(),
            1
        );
    }

    #[test]
    fn detects_jwt_like_token() {
        let jwt = [
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
            ".eyJzdWIiOiIxMjM0NTY3ODkwIn0",
            ".SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
        ]
        .concat();
        assert_eq!(
            check_rule("secrets:jwt-like-token", &format!("const t = \"{jwt}\";\n")).len(),
            1
        );
    }

    #[test]
    fn ignores_clean_code() {
        let code = "function add(a: number, b: number): number {\n  return a + b;\n}\n";
        for spec in PROVIDER_SPECS {
            assert!(
                check_rule(spec.id, code).is_empty(),
                "false positive on {}",
                spec.id
            );
        }
    }
}
