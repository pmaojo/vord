//! Rule: flags setting overly permissive file permissions (e.g., world-writable).

use yunq_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use yunq_rules_engine::{Finding, IssueType, Rule, RuleId, Severity};

pub struct InsecureFilePermissionsRule {
    id: RuleId,
}

impl InsecureFilePermissionsRule {
    pub fn new() -> Self {
        Self {
            id: RuleId::new("owasp:insecure-file-permissions").expect("valid rule id"),
        }
    }
}

impl Default for InsecureFilePermissionsRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for InsecureFilePermissionsRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn applies_to(&self, lang: &LanguageIdentifier) -> bool {
        *lang == LanguageIdentifier::typescript()
            || *lang == LanguageIdentifier::python()
            || *lang == LanguageIdentifier::go()
    }

    fn default_severity(&self) -> Severity {
        Severity::Critical
    }

    fn issue_type(&self) -> IssueType {
        IssueType::Vulnerability
    }

    fn metadata(&self) -> yunq_rules_engine::RuleMetadata {
        yunq_rules_engine::RuleMetadata {
            description: "Setting excessively permissive file permissions (e.g., world-writable) allows unauthorized users to read, modify, or execute files.".into(),
            tags: vec!["security".into(), "owasp-a01".into(), "cwe-732".into()],
            cwe: Some(732),
            produces_hotspots: false,
        }
    }

    fn check(&self, file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        if yunq_rules_engine::is_test_only_path(file.path()) {
            return Vec::new();
        }

        let mut findings = Vec::new();
        let is_ts = *file.language() == LanguageIdentifier::typescript();
        let is_py = *file.language() == LanguageIdentifier::python();
        let is_go = *file.language() == LanguageIdentifier::go();

        for call in ast.descendants().filter(|n| *n.kind() == NodeKind::Call) {
            let Some(callee) = call.first_child() else {
                continue;
            };
            let callee_text = callee.text();

            let matches_ts = is_ts && (callee_text == "fs.chmod" || callee_text == "fs.chmodSync");
            let matches_py = is_py && (callee_text == "os.chmod");
            let matches_go = is_go && (callee_text == "os.Chmod");

            if !matches_ts && !matches_py && !matches_go {
                continue;
            }

            // Find the arguments. For TS and Go it's generally index 1 or similar,
            // but we can just look for the numeric literals in the arguments.
            // Or look at children of the argument list.
            let mut has_insecure_mask = false;

            // TS, Python, Go parse arguments slightly differently, but they are generally
            // children of the Call node (or inside an argument_list child).
            // Let's just traverse all children of the Call node to find the mask.
            for arg_node in call.descendants() {
                // If it's a number/int literal or we just check the text of descendants
                // that represent the permission bits.
                let text = arg_node.text();
                // Insecure masks: 0777, 0o777, 0666, 0o666
                // In python: 511 (0777 in decimal), 438 (0666 in decimal)
                if text == "0777"
                    || text == "0o777"
                    || text == "0666"
                    || text == "0o666"
                    || (is_py && (text == "511" || text == "438"))
                {
                    has_insecure_mask = true;
                    break;
                }
            }

            if has_insecure_mask {
                findings.push(Finding::new(
                    "Setting file permissions to be world-writable (e.g., 0777 or 0666) is insecure.",
                    call.span(),
                ));
            }
        }
        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use yunq_rules_engine::AstParser;

    fn check_ts(code: &str) -> Vec<Finding> {
        let file = SourceFile::new("app.ts", code, LanguageIdentifier::typescript()).unwrap();
        let ast = yunq_parser_typescript::TypeScriptParser::new()
            .parse(&file)
            .unwrap();
        InsecureFilePermissionsRule::new().check(&file, &ast)
    }

    fn check_py(code: &str) -> Vec<Finding> {
        let file = SourceFile::new("app.py", code, LanguageIdentifier::python()).unwrap();
        let ast = yunq_parser_python::PythonParser::new()
            .parse(&file)
            .unwrap();
        InsecureFilePermissionsRule::new().check(&file, &ast)
    }

    fn check_go(code: &str) -> Vec<Finding> {
        let file = SourceFile::new("app.go", code, LanguageIdentifier::go()).unwrap();
        let ast = yunq_parser_go::GoParser::new().parse(&file).unwrap();
        InsecureFilePermissionsRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_ts_chmod_777() {
        assert_eq!(check_ts("fs.chmodSync('file.txt', 0o777);\n").len(), 1);
        assert_eq!(check_ts("fs.chmod('file.txt', 0o666, cb);\n").len(), 1);
        assert_eq!(check_ts("fs.chmodSync('file.txt', 0777);\n").len(), 1);
    }

    #[test]
    fn allows_ts_safe_chmod() {
        assert!(check_ts("fs.chmodSync('file.txt', 0o644);\n").is_empty());
    }

    #[test]
    fn flags_py_chmod_777() {
        assert_eq!(check_py("os.chmod('file.txt', 0o777)\n").len(), 1);
        assert_eq!(check_py("os.chmod('file.txt', 511)\n").len(), 1);
        assert_eq!(check_py("os.chmod('file.txt', 0o666)\n").len(), 1);
        assert_eq!(check_py("os.chmod('file.txt', 438)\n").len(), 1);
    }

    #[test]
    fn allows_py_safe_chmod() {
        assert!(check_py("os.chmod('file.txt', 0o600)\n").is_empty());
    }

    #[test]
    fn flags_go_chmod_777() {
        assert_eq!(check_go("os.Chmod(\"file.txt\", 0777)\n").len(), 1);
        assert_eq!(check_go("os.Chmod(\"file.txt\", 0666)\n").len(), 1);
    }

    #[test]
    fn allows_go_safe_chmod() {
        assert!(check_go("os.Chmod(\"file.txt\", 0644)\n").is_empty());
    }
}
