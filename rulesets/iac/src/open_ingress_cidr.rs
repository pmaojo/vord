//! Rule: flags network ingress/security-group rules opened to the entire
//! internet (`0.0.0.0/0`) in Terraform or Kubernetes/CloudFormation YAML.

use yunq_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use yunq_rules_engine::{Finding, IssueType, Rule, RuleId, RuleMetadata, Severity};

const OPEN_CIDR: &str = "0.0.0.0/0";

pub struct OpenIngressCidrRule {
    id: RuleId,
}

impl OpenIngressCidrRule {
    pub fn new() -> Self {
        Self {
            id: RuleId::new("iac:open-ingress-cidr").expect("valid rule id"),
        }
    }
}

impl Default for OpenIngressCidrRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for OpenIngressCidrRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn applies_to(&self, lang: &LanguageIdentifier) -> bool {
        *lang == LanguageIdentifier::hcl()
            || *lang == LanguageIdentifier::yaml()
            || *lang == LanguageIdentifier::json()
    }

    fn default_severity(&self) -> Severity {
        Severity::Critical
    }

    fn issue_type(&self) -> IssueType {
        IssueType::Vulnerability
    }

    fn remediation_effort_minutes(&self) -> u32 {
        15
    }

    fn metadata(&self) -> RuleMetadata {
        RuleMetadata {
            description: "A security-group/network-policy ingress rule allows traffic from the entire internet (0.0.0.0/0); restrict the CIDR to the ranges that actually need access.".into(),
            tags: vec!["security".into(), "iac".into(), "owasp-a05".into()],
            cwe: Some(284),
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
            if lower.contains(OPEN_CIDR) && (lower.contains("cidr") || lower.contains("ingress")) {
                findings.push(Finding::new(
                    "Ingress rule open to 0.0.0.0/0 (the entire internet); scope the CIDR to trusted ranges",
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
        AstNode::new(
            NodeKind::SourceUnit,
            yunq_ast::Span::new(1, 1, 1, code.len() as u32),
            code,
            vec![],
        )
    }

    #[test]
    fn flags_terraform_open_ingress_cidr() {
        let code = "ingress {\n  from_port = 22\n  cidr_blocks = [\"0.0.0.0/0\"]\n}\n";
        let file = SourceFile::new("main.tf", code, LanguageIdentifier::hcl()).unwrap();
        let findings = OpenIngressCidrRule::new().check(&file, &source_unit(code));
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn flags_cloudformation_open_cidr() {
        let code = "{\n  \"IpPermissions\": [{ \"CidrIp\": \"0.0.0.0/0\", \"FromPort\": 22 }]\n}\n";
        let file = SourceFile::new("stack.json", code, LanguageIdentifier::json()).unwrap();
        let findings = OpenIngressCidrRule::new().check(&file, &source_unit(code));
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn allows_restricted_cidr() {
        let code = "ingress {\n  from_port = 22\n  cidr_blocks = [\"10.0.0.0/16\"]\n}\n";
        let file = SourceFile::new("main.tf", code, LanguageIdentifier::hcl()).unwrap();
        let findings = OpenIngressCidrRule::new().check(&file, &source_unit(code));
        assert!(findings.is_empty());
    }

    #[test]
    fn ignores_open_cidr_outside_network_context() {
        let code = "variable \"anything\" {\n  default = \"0.0.0.0/0\"\n}\n";
        let file = SourceFile::new("main.tf", code, LanguageIdentifier::hcl()).unwrap();
        let findings = OpenIngressCidrRule::new().check(&file, &source_unit(code));
        assert!(findings.is_empty());
    }
}
