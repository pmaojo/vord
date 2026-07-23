//! Rule: flags Dockerfiles that run as root (missing USER instruction).

use yunq_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use yunq_rules_engine::{Finding, IssueType, Rule, RuleId, Severity};

pub struct DockerfileRootUserRule {
    id: RuleId,
}

impl DockerfileRootUserRule {
    pub fn new() -> Self {
        let id = match RuleId::new("owasp:dockerfile-root-user") {
            Ok(id) => id,
            Err(_) => unreachable!(),
        };
        Self { id }
    }
}

impl Default for DockerfileRootUserRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for DockerfileRootUserRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn applies_to(&self, lang: &LanguageIdentifier) -> bool {
        lang == &LanguageIdentifier::dockerfile()
    }

    fn default_severity(&self) -> Severity {
        Severity::Critical
    }

    fn issue_type(&self) -> IssueType {
        IssueType::Vulnerability
    }

    fn check(&self, file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        if ast.kind() != &NodeKind::SourceUnit {
            return Vec::new();
        }

        let content = file.content();
        let has_user = content.lines().any(|line| line.trim().starts_with("USER "));

        if !has_user && content.contains("FROM ") {
            vec![Finding::new(
                "Dockerfile does not specify a non-root USER instruction (runs as root by default)",
                ast.span(),
            )]
        } else {
            Vec::new()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_dockerfile_without_user() {
        let code = "FROM alpine:3.18\nRUN echo hi\n";
        let file = SourceFile::new("Dockerfile", code, LanguageIdentifier::dockerfile()).unwrap();
        let ast = AstNode::new(NodeKind::SourceUnit, yunq_ast::Span::new(1, 1, 3, 1), code, vec![]);
        let rule = DockerfileRootUserRule::new();

        let findings = rule.check(&file, &ast);
        assert_eq!(findings.len(), 1);
    }
}
