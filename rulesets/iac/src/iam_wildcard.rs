//! Rule: flags IAM/RBAC policy statements that grant wildcard actions or
//! resources (Terraform `aws_iam_policy_document`, raw IAM JSON policies,
//! Kubernetes `Role`/`ClusterRole` rules).

use yunq_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use yunq_rules_engine::{Finding, Rule, RuleId, RuleMetadata, Severity};

const MARKERS: &[&str] = &[
    "\"action\": \"*\"",
    "\"action\":\"*\"",
    "actions = [\"*\"]",
    "actions=[\"*\"]",
    "\"resource\": \"*\"",
    "\"resource\":\"*\"",
    "resources = [\"*\"]",
    "resources=[\"*\"]",
    "resources: [\"*\"]",
    "verbs: [\"*\"]",
];

pub struct IamWildcardPermissionRule {
    id: RuleId,
}

impl IamWildcardPermissionRule {
    pub fn new() -> Self {
        Self { id: RuleId::new("iac:iam-wildcard-permission").expect("valid rule id") }
    }
}

impl Default for IamWildcardPermissionRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for IamWildcardPermissionRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn applies_to(&self, lang: &LanguageIdentifier) -> bool {
        *lang == LanguageIdentifier::hcl() || *lang == LanguageIdentifier::yaml() || *lang == LanguageIdentifier::json()
    }

    fn default_severity(&self) -> Severity {
        Severity::Major
    }

    fn remediation_effort_minutes(&self) -> u32 {
        20
    }

    fn metadata(&self) -> RuleMetadata {
        RuleMetadata {
            description: "IAM/RBAC statements granting wildcard actions or resources violate least privilege; scope the policy to the specific actions and resources it needs.".into(),
            tags: vec!["security".into(), "iac".into(), "owasp-a01".into()],
            cwe: Some(732),
            produces_hotspots: true,
        }
    }

    fn check(&self, file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        if ast.kind() != &NodeKind::SourceUnit {
            return Vec::new();
        }

        let mut findings = Vec::new();
        for (idx, line) in file.content().lines().enumerate() {
            let trimmed = line.trim();
            if trimmed.starts_with('#') || trimmed.starts_with("//") {
                continue;
            }
            let lower = line.to_ascii_lowercase();
            if let Some(marker) = MARKERS.iter().find(|m| lower.contains(*m)) {
                findings.push(Finding::new(
                    format!("Wildcard permission grant via '{marker}'; scope actions/resources to least privilege"),
                    yunq_ast::Span::new((idx + 1) as u32, 1, (idx + 1) as u32, line.len().max(1) as u32),
                ));
            }
        }
        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn source_unit(code: &str) -> AstNode {
        AstNode::new(NodeKind::SourceUnit, yunq_ast::Span::new(1, 1, 1, code.len() as u32), code, vec![])
    }

    #[test]
    fn flags_terraform_wildcard_actions() {
        let code = "statement {\n  actions = [\"*\"]\n  resources = [\"arn:aws:s3:::bucket\"]\n}\n";
        let file = SourceFile::new("main.tf", code, LanguageIdentifier::hcl()).unwrap();
        let findings = IamWildcardPermissionRule::new().check(&file, &source_unit(code));
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn flags_json_policy_wildcard_action() {
        let code = "{\n  \"Action\": \"*\",\n  \"Effect\": \"Allow\"\n}\n";
        let file = SourceFile::new("policy.json", code, LanguageIdentifier::json()).unwrap();
        let findings = IamWildcardPermissionRule::new().check(&file, &source_unit(code));
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn flags_k8s_wildcard_verbs() {
        let code = "rules:\n- apiGroups: [\"\"]\n  resources: [\"pods\"]\n  verbs: [\"*\"]\n";
        let file = SourceFile::new("role.yaml", code, LanguageIdentifier::yaml()).unwrap();
        let findings = IamWildcardPermissionRule::new().check(&file, &source_unit(code));
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn allows_scoped_actions() {
        let code = "statement {\n  actions = [\"s3:GetObject\"]\n  resources = [\"arn:aws:s3:::bucket/*\"]\n}\n";
        let file = SourceFile::new("main.tf", code, LanguageIdentifier::hcl()).unwrap();
        let findings = IamWildcardPermissionRule::new().check(&file, &source_unit(code));
        assert!(findings.is_empty());
    }

    #[test]
    fn applies_only_to_iac_languages() {
        let rule = IamWildcardPermissionRule::new();
        assert!(rule.applies_to(&LanguageIdentifier::hcl()));
        assert!(rule.applies_to(&LanguageIdentifier::yaml()));
        assert!(!rule.applies_to(&LanguageIdentifier::typescript()));
    }
}
