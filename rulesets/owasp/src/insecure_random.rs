use vord_ast::{AstNode, LanguageIdentifier, SourceFile};
use vord_rules_engine::{Finding, IssueType, Rule, RuleId, Severity};

pub struct InsecureRandomRule {
    id: RuleId,
}

impl InsecureRandomRule {
    pub fn new() -> Self {
        Self {
            id: RuleId::new("owasp:insecure-random").expect("valid rule id"),
        }
    }
}

impl Default for InsecureRandomRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for InsecureRandomRule {
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
            description: "Usage of insecure random number generators (e.g. Math.random() in JS, random in Python) is unsafe for cryptographic purposes. Use a cryptographically secure pseudo-random number generator (CSPRNG) instead.".into(),
            tags: vec!["security".into(), "owasp-a02".into(), "crypto".into()],
            cwe: Some(330), // CWE-330: Use of Insufficiently Random Values
            produces_hotspots: false,
        }
    }

    fn check(&self, file: &SourceFile, _ast: &AstNode) -> Vec<Finding> {
        let is_python = *file.language() == LanguageIdentifier::python();
        let is_ts = *file.language() == LanguageIdentifier::typescript();

        if !is_python && !is_ts {
            return vec![];
        }

        let content = file.content();
        let mut findings = vec![];
        for (idx, line) in content.lines().enumerate() {
            let trimmed = line.trim();
            if trimmed.starts_with("//") || trimmed.starts_with('#') || trimmed.starts_with('*') {
                continue;
            }

            if is_ts {
                if line.contains("Math.random") {
                    findings.push(Finding::new(
                        "Math.random() is not cryptographically secure. Prefer crypto.getRandomValues() or crypto.randomBytes()",
                        vord_ast::Span::new((idx + 1) as u32, 1, (idx + 1) as u32, line.len().max(1) as u32),
                    ));
                }
            } else if is_python {
                // In Python, 'random' module is not secure. Functions like random.random(), random.randint(), random.choice(), etc.
                // We will look for calls to random.* where the module is 'random'
                if line.contains("random.random")
                    || line.contains("random.randint")
                    || line.contains("random.choice")
                    || line.contains("random.randrange")
                    || line.contains("random.sample")
                    || line.contains("random.uniform")
                {
                    findings.push(Finding::new(
                        "The 'random' module is not cryptographically secure. Prefer the 'secrets' module.",
                        vord_ast::Span::new((idx + 1) as u32, 1, (idx + 1) as u32, line.len().max(1) as u32),
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
    use vord_ast::NodeKind;

    #[test]
    fn flags_math_random() {
        let code = "const val = Math.random();\n";
        let file = SourceFile::new("app.ts", code, LanguageIdentifier::typescript()).unwrap();
        let ast = AstNode::new(
            NodeKind::SourceUnit,
            vord_ast::Span::new(1, 1, 1, code.len() as u32),
            code,
            vec![],
        );
        let findings = InsecureRandomRule::new().check(&file, &ast);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn flags_python_random() {
        let code = "import random\nval = random.randint(1, 10)\n";
        let file = SourceFile::new("app.py", code, LanguageIdentifier::python()).unwrap();
        let ast = AstNode::new(
            NodeKind::SourceUnit,
            vord_ast::Span::new(1, 1, 1, code.len() as u32),
            code,
            vec![],
        );
        let findings = InsecureRandomRule::new().check(&file, &ast);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn allows_python_secrets() {
        let code = "import secrets\nval = secrets.randbelow(10)\n";
        let file = SourceFile::new("app.py", code, LanguageIdentifier::python()).unwrap();
        let ast = AstNode::new(
            NodeKind::SourceUnit,
            vord_ast::Span::new(1, 1, 1, code.len() as u32),
            code,
            vec![],
        );
        let findings = InsecureRandomRule::new().check(&file, &ast);
        assert!(findings.is_empty());
    }

    #[test]
    fn ignores_comments() {
        let code = "// Math.random is bad\n";
        let file = SourceFile::new("app.ts", code, LanguageIdentifier::typescript()).unwrap();
        let ast = AstNode::new(
            NodeKind::SourceUnit,
            vord_ast::Span::new(1, 1, 1, code.len() as u32),
            code,
            vec![],
        );
        let findings = InsecureRandomRule::new().check(&file, &ast);
        assert!(findings.is_empty());
    }
}
