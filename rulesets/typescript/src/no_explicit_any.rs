//! Rule: flags explicit `: any` or `as any` type annotations and type assertions in TypeScript files.

use yunq_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use yunq_rules_engine::{Finding, IssueType, Rule, RuleId, RuleMetadata, Severity};

fn is_explicit_any(line: &str) -> bool {
    let bytes = line.as_bytes();
    let n = bytes.len();
    let mut i = 0;

    while i < n {
        // Check for `: any` or `:any`
        if bytes[i] == b':' {
            let mut j = i + 1;
            while j < n && (bytes[j] == b' ' || bytes[j] == b'\t') {
                j += 1;
            }
            if j + 3 <= n && &bytes[j..j + 3] == b"any" {
                let end = j + 3;
                if end == n || (!bytes[end].is_ascii_alphanumeric() && bytes[end] != b'_') {
                    return true;
                }
            }
        }

        // Check for `as any`
        if (i == 0 || (!bytes[i - 1].is_ascii_alphanumeric() && bytes[i - 1] != b'_'))
            && i + 2 <= n
            && &bytes[i..i + 2] == b"as"
        {
            let mut j = i + 2;
            if j < n && (bytes[j] == b' ' || bytes[j] == b'\t') {
                while j < n && (bytes[j] == b' ' || bytes[j] == b'\t') {
                    j += 1;
                }
                if j + 3 <= n && &bytes[j..j + 3] == b"any" {
                    let end = j + 3;
                    if end == n || (!bytes[end].is_ascii_alphanumeric() && bytes[end] != b'_') {
                        return true;
                    }
                }
            }
        }

        // Check for `<any>`
        if bytes[i] == b'<' && i + 5 <= n && &bytes[i..i + 5] == b"<any>" {
            return true;
        }

        i += 1;
    }

    false
}

pub struct NoExplicitAnyRule {
    id: RuleId,
}

impl NoExplicitAnyRule {
    pub fn new() -> Self {
        Self {
            id: RuleId::new("typescript:no-explicit-any").expect("valid rule id"),
        }
    }
}

impl Default for NoExplicitAnyRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for NoExplicitAnyRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn applies_to(&self, language: &LanguageIdentifier) -> bool {
        *language == LanguageIdentifier::typescript()
    }

    fn default_severity(&self) -> Severity {
        Severity::Major
    }

    fn issue_type(&self) -> IssueType {
        IssueType::CodeSmell
    }

    fn metadata(&self) -> RuleMetadata {
        RuleMetadata {
            description: "Avoid explicit `: any` type annotations or `as any` type assertions; using `any` disables type safety. Prefer specific types or `unknown`.".into(),
            tags: vec!["typescript".into(), "type-safety".into(), "code-quality".into()],
            cwe: Some(704),
            produces_hotspots: false,
        }
    }

    fn check(&self, file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        if ast.kind() != &NodeKind::SourceUnit {
            return Vec::new();
        }
        if yunq_rules_engine::is_test_only_path(file.path()) {
            return Vec::new();
        }

        let mut findings = Vec::new();
        let content = file.content();

        for (idx, line) in content.lines().enumerate() {
            let line_no = (idx + 1) as u32;
            let trimmed = line.trim();
            if trimmed.starts_with("//") || trimmed.starts_with('*') || trimmed.starts_with("/*") {
                continue;
            }

            if is_explicit_any(line) {
                findings.push(Finding::new(
                    "Avoid explicit `: any` type annotations or `as any` type assertions; prefer specific types or `unknown`",
                    yunq_ast::Span::new(line_no, 1, line_no, line.len().max(1) as u32),
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
    fn flags_explicit_any_type_annotation() {
        let code = "const data: any = 123;\n";
        let file = SourceFile::new("app.ts", code, LanguageIdentifier::typescript()).unwrap();
        let ast = AstNode::new(
            NodeKind::SourceUnit,
            yunq_ast::Span::new(1, 1, 1, code.len() as u32),
            code,
            vec![],
        );
        let rule = NoExplicitAnyRule::new();
        let findings = rule.check(&file, &ast);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn flags_as_any_assertion() {
        let code = "const val = data as any;\n";
        let file = SourceFile::new("app.ts", code, LanguageIdentifier::typescript()).unwrap();
        let ast = AstNode::new(
            NodeKind::SourceUnit,
            yunq_ast::Span::new(1, 1, 1, code.len() as u32),
            code,
            vec![],
        );
        let rule = NoExplicitAnyRule::new();
        let findings = rule.check(&file, &ast);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn flags_function_param_any() {
        let code = "function handle(event: any): void {}\n";
        let file = SourceFile::new("app.ts", code, LanguageIdentifier::typescript()).unwrap();
        let ast = AstNode::new(
            NodeKind::SourceUnit,
            yunq_ast::Span::new(1, 1, 1, code.len() as u32),
            code,
            vec![],
        );
        let rule = NoExplicitAnyRule::new();
        let findings = rule.check(&file, &ast);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn allows_specific_types_or_unknown() {
        let code = "const data: unknown = 123;\nconst name: string = 'test';\n";
        let file = SourceFile::new("app.ts", code, LanguageIdentifier::typescript()).unwrap();
        let ast = AstNode::new(
            NodeKind::SourceUnit,
            yunq_ast::Span::new(1, 1, 1, code.len() as u32),
            code,
            vec![],
        );
        let rule = NoExplicitAnyRule::new();
        let findings = rule.check(&file, &ast);
        assert!(findings.is_empty());
    }

    #[test]
    fn ignores_comments() {
        let code = "// const data: any = 123;\n";
        let file = SourceFile::new("app.ts", code, LanguageIdentifier::typescript()).unwrap();
        let ast = AstNode::new(
            NodeKind::SourceUnit,
            yunq_ast::Span::new(1, 1, 1, code.len() as u32),
            code,
            vec![],
        );
        let rule = NoExplicitAnyRule::new();
        let findings = rule.check(&file, &ast);
        assert!(findings.is_empty());
    }
}
