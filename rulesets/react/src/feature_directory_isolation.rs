use vord_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use vord_rules_engine::{declare_rule_id, Finding, IssueType, Rule, RuleId, Severity};

declare_rule_id!(FeatureDirectoryIsolationRule, "react:feature-directory-isolation");

impl Rule for FeatureDirectoryIsolationRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn applies_to(&self, language: &LanguageIdentifier) -> bool {
        language.is_typescript() || language.is_javascript()
    }

    fn default_severity(&self) -> Severity {
        Severity::Major
    }

    fn issue_type(&self) -> IssueType {
        IssueType::CodeSmell
    }

    fn check(&self, file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        let mut findings = Vec::new();

        fn walk(node: &AstNode, file: &SourceFile, out: &mut Vec<Finding>) {
            // tree-sitter-typescript: import_statement -> source: string
            if matches!(node.kind(), NodeKind::Other(k) if k.as_ref() == "import_statement") {
                for child in node.children() {
                    if *child.kind() == NodeKind::StringLiteral || matches!(child.kind(), NodeKind::Other(k) if k.as_ref() == "string") {
                        let text = child.text().trim_matches(&['\'', '"', '`'][..]);
                        if is_deep_feature_import(text, file.path()) {
                            out.push(Finding::new(
                                format!(
                                    "Deep import `{}` breaches feature module boundary. Import from the feature index (`features/<feature>`) instead.",
                                    text
                                ),
                                child.span(),
                            ));
                        }
                    }
                }
            }
            for child in node.children() {
                walk(child, file, out);
            }
        }

        walk(ast, file, &mut findings);
        findings
    }
}

fn is_deep_feature_import(import_spec: &str, current_file_path: &str) -> bool {
    // E.g. "@/features/auth/components/Button" or "../auth/api/login"
    if import_spec.contains("features/") || import_spec.contains("features\\") {
        let parts: Vec<&str> = import_spec.split(['/', '\\']).collect();
        if let Some(idx) = parts.iter().position(|&p| p == "features") {
            // If there are more than 2 elements after "features" (e.g. features -> auth -> components -> Button)
            if parts.len() > idx + 2 {
                // Check if current file is in the same feature
                let current_parts: Vec<&str> = current_file_path.split(['/', '\\']).collect();
                if let Some(c_idx) = current_parts.iter().position(|&p| p == "features") {
                    if current_parts.len() > c_idx + 1 && parts.len() > idx + 1 && current_parts[c_idx + 1] == parts[idx + 1] {
                        // Internal import inside the SAME feature is allowed
                        return false;
                    }
                }
                return true;
            }
        }
    }
    false
}
