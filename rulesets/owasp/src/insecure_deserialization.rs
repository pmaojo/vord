//! Rule: flags deserialization of untrusted data via unsafe APIs
//! (Python pickle/PyYAML, Java ObjectInputStream, Ruby Marshal, PHP unserialize).

use yunq_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use yunq_rules_engine::{Finding, IssueType, Rule, RuleId, Severity};

const UNSAFE_MARKERS: &[&str] = &[
    "pickle.loads",
    "pickle.load(",
    "ObjectInputStream",
    "readObject",
    "Marshal.load",
    "unserialize(",
];

pub struct InsecureDeserializationRule {
    id: RuleId,
}

impl InsecureDeserializationRule {
    pub fn new() -> Self {
        Self {
            id: RuleId::new("owasp:insecure-deserialization").expect("valid rule id"),
        }
    }
}

impl Default for InsecureDeserializationRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for InsecureDeserializationRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn applies_to(&self, lang: &LanguageIdentifier) -> bool {
        *lang == LanguageIdentifier::python()
            || *lang == LanguageIdentifier::java()
            || *lang == LanguageIdentifier::ruby()
            || *lang == LanguageIdentifier::php()
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

        let mut findings = Vec::new();
        for (idx, line) in file.content().lines().enumerate() {
            let trimmed = line.trim();
            if trimmed.starts_with("//") || trimmed.starts_with('#') || trimmed.starts_with('*') {
                continue;
            }

            if let Some(marker) = UNSAFE_MARKERS.iter().find(|m| line.contains(*m)) {
                findings.push(Finding::new(
                    format!(
                        "Deserializing untrusted data via '{marker}' can execute arbitrary code; use a safe/restricted deserializer"
                    ),
                    yunq_ast::Span::new((idx + 1) as u32, 1, (idx + 1) as u32, line.len().max(1) as u32),
                ));
                continue;
            }

            if line.contains("yaml.load(")
                && !line.contains("Loader=")
                && !line.contains("safe_load")
            {
                findings.push(Finding::new(
                    "yaml.load() without a restricted Loader can execute arbitrary code; use yaml.safe_load() or Loader=yaml.SafeLoader",
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

    #[test]
    fn flags_python_pickle_loads() {
        let code = "data = pickle.loads(request.body)\n";
        let file = SourceFile::new("app.py", code, LanguageIdentifier::python()).unwrap();
        let ast = AstNode::new(
            NodeKind::SourceUnit,
            yunq_ast::Span::new(1, 1, 1, code.len() as u32),
            code,
            vec![],
        );
        let findings = InsecureDeserializationRule::new().check(&file, &ast);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn flags_unsafe_yaml_load() {
        let code = "cfg = yaml.load(stream)\n";
        let file = SourceFile::new("app.py", code, LanguageIdentifier::python()).unwrap();
        let ast = AstNode::new(
            NodeKind::SourceUnit,
            yunq_ast::Span::new(1, 1, 1, code.len() as u32),
            code,
            vec![],
        );
        let findings = InsecureDeserializationRule::new().check(&file, &ast);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn allows_safe_yaml_load() {
        let code = "cfg = yaml.safe_load(stream)\n";
        let file = SourceFile::new("app.py", code, LanguageIdentifier::python()).unwrap();
        let ast = AstNode::new(
            NodeKind::SourceUnit,
            yunq_ast::Span::new(1, 1, 1, code.len() as u32),
            code,
            vec![],
        );
        let findings = InsecureDeserializationRule::new().check(&file, &ast);
        assert!(findings.is_empty());
    }

    #[test]
    fn flags_java_object_input_stream() {
        let code = "Object o = new ObjectInputStream(in).readObject();\n";
        let file = SourceFile::new("App.java", code, LanguageIdentifier::java()).unwrap();
        let ast = AstNode::new(
            NodeKind::SourceUnit,
            yunq_ast::Span::new(1, 1, 1, code.len() as u32),
            code,
            vec![],
        );
        let findings = InsecureDeserializationRule::new().check(&file, &ast);
        assert_eq!(findings.len(), 1);
    }
}
