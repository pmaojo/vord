//! Rule: flags `tarfile.extractall()` and `tarfile.extract()` without a `filter`
//! argument. Extracting untrusted tarballs can lead to path traversal vulnerabilities
//! (e.g., overwriting system files) if the archive contains absolute paths or `..` components.
//! Python 3.12 introduced a `filter='data'` argument to mitigate this, and it will become
//! the default in 3.14.

use vord_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use vord_rules_engine::{Finding, IssueType, Rule, RuleId, Severity};

fn other_kind_name(node: &AstNode) -> Option<&str> {
    match node.kind() {
        NodeKind::Other(name) => Some(name.as_ref()),
        _ => None,
    }
}

fn has_filter_argument(call: &AstNode) -> bool {
    let Some(args) = call
        .children()
        .iter()
        .find(|c| other_kind_name(c) == Some("argument_list"))
    else {
        return false;
    };
    args.children().iter().any(|arg| {
        other_kind_name(arg) == Some("keyword_argument")
            && arg
                .children()
                .first()
                .is_some_and(|name| name.text() == "filter")
    })
}

pub struct TarfileUnsafeExtractionRule {
    id: RuleId,
}

impl TarfileUnsafeExtractionRule {
    pub fn new() -> Self {
        Self {
            id: RuleId::new("python:tarfile-unsafe-extraction").expect("valid rule id"),
        }
    }
}

impl Default for TarfileUnsafeExtractionRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for TarfileUnsafeExtractionRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn applies_to(&self, lang: &LanguageIdentifier) -> bool {
        *lang == LanguageIdentifier::python()
    }

    fn default_severity(&self) -> Severity {
        Severity::Critical
    }

    fn issue_type(&self) -> IssueType {
        IssueType::Vulnerability
    }

    fn remediation_effort_minutes(&self) -> u32 {
        10
    }

    fn metadata(&self) -> vord_rules_engine::RuleMetadata {
        vord_rules_engine::RuleMetadata {
            description: "tarfile.extractall and tarfile.extract are vulnerable to path traversal (Zip Slip) when processing untrusted archives. Use filter='data' (introduced in Python 3.12) to prevent this.".into(),
            tags: vec!["security".into(), "path-traversal".into(), "cwe".into()],
            cwe: Some(22),
            produces_hotspots: false,
        }
    }

    fn check(&self, file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        if vord_rules_engine::is_test_only_path(file.path()) {
            return Vec::new();
        }

        // Fast path: if the file doesn't even mention 'extractall' or 'extract', skip full tree walk.
        let content = file.content();
        if !content.contains("extractall") && !content.contains("extract") {
            return Vec::new();
        }

        ast.descendants()
            .filter(|n| *n.kind() == NodeKind::Call)
            .filter(|call| {
                if let Some(callee) = call.first_child() {
                    if callee.kind() == &NodeKind::MemberAccess {
                        if let Some(method) = callee.children().last() {
                            return method.text() == "extractall" || method.text() == "extract";
                        }
                    }
                }
                false
            })
            .filter(|call| !has_filter_argument(call))
            .map(|call| Finding::new("tarfile extraction without a filter argument is vulnerable to path traversal (Zip Slip); pass filter='data' to mitigate.", call.span()))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use vord_rules_engine::AstParser;

    use super::*;

    fn findings(code: &str) -> Vec<Finding> {
        let file = SourceFile::new("t.py", code, LanguageIdentifier::python()).unwrap();
        let ast = vord_parser_python::PythonParser::new()
            .parse(&file)
            .unwrap();
        TarfileUnsafeExtractionRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_extractall_without_filter() {
        assert_eq!(findings("tar.extractall(path='/tmp/')\n").len(), 1);
    }

    #[test]
    fn flags_extract_without_filter() {
        assert_eq!(findings("tar.extract(member, path='/tmp/')\n").len(), 1);
    }

    #[test]
    fn allows_extractall_with_filter() {
        assert!(findings("tar.extractall(path='/tmp/', filter='data')\n").is_empty());
    }

    #[test]
    fn allows_extract_with_filter() {
        assert!(findings("tar.extract(member, path='/tmp/', filter='data')\n").is_empty());
    }
}
