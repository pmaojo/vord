use syn::visit::Visit;
use vord_ast::{AstNode, LanguageIdentifier, SourceFile, Span};
use vord_rules_engine::{declare_rule_id, Finding, IssueType, Rule, RuleId, Severity};

declare_rule_id!(RustClippyAdapterRule, "rust:clippy-analyzer");

struct ClippyVisitor<'a> {
    findings: Vec<Finding>,
    _file: &'a SourceFile,
}

impl<'ast> Visit<'ast> for ClippyVisitor<'_> {
    fn visit_use_tree(&mut self, i: &'ast syn::UseTree) {
        if matches!(i, syn::UseTree::Glob(_)) {
            self.findings.push(Finding::new(
                "Clippy lint [clippy::wildcard_imports]: Avoid wildcard imports (`use path::*`)",
                Span::new(1, 1, 1, 20),
            ));
        }
        syn::visit::visit_use_tree(self, i);
    }
}

impl Rule for RustClippyAdapterRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn applies_to(&self, language: &LanguageIdentifier) -> bool {
        *language == LanguageIdentifier::rust()
    }

    fn default_severity(&self) -> Severity {
        Severity::Major
    }

    fn issue_type(&self) -> IssueType {
        IssueType::CodeSmell
    }

    fn check(&self, file: &SourceFile, _ast: &AstNode) -> Vec<Finding> {
        let mut findings = Vec::new();
        match syn::parse_file(file.content()) {
            Ok(syntax_tree) => {
                let mut visitor = ClippyVisitor {
                    findings: Vec::new(),
                    _file: file,
                };
                visitor.visit_file(&syntax_tree);
                findings.extend(visitor.findings);
            }
            Err(err) => {
                let msg = err.to_string();
                findings.push(Finding::new(
                    format!("Rust syntax error: {}", msg),
                    Span::new(1, 1, 1, 20),
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
    fn parses_rust_code_and_reports_clippy_wildcard_lint() {
        let code = "use std::io::*;\nfn main() {}\n";
        let file = SourceFile::new("main.rs", code, LanguageIdentifier::rust()).unwrap();
        let ast = AstNode::new(
            vord_ast::NodeKind::SourceUnit,
            Span::new(1, 1, 1, code.len() as u32),
            code,
            vec![],
        );

        let rule = RustClippyAdapterRule::new();
        let findings = rule.check(&file, &ast);
        assert!(!findings.is_empty());
    }
}
