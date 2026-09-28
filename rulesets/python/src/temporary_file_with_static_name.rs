//! Rule: flags `open(...)` given a hardcoded path under a shared temp
//! directory (`/tmp/...`, `/var/tmp/...`, `C:\Temp\...`). A static name in
//! a world-writable directory lets any other process on the same host
//! read, replace, or symlink-race the file before this one gets to it;
//! `tempfile.mkstemp()`/`NamedTemporaryFile()` generate a unique,
//! privately-created name instead. Complements `python:insecure-tempfile`,
//! which flags `tempfile.mktemp()` specifically rather than a hardcoded
//! path literal passed to `open()`.

use vord_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use vord_rules_engine::{Finding, IssueType, Rule, RuleId, Severity};

use crate::common::other_kind_name;

fn literal_string_value(arg: &AstNode) -> Option<String> {
    if arg.kind() != &NodeKind::StringLiteral {
        return None;
    }
    let content: String = arg
        .children()
        .iter()
        .filter(|c| other_kind_name(c) == Some("string_content"))
        .map(|c| c.text())
        .collect();
    Some(content)
}

fn looks_like_shared_temp_path(path: &str) -> bool {
    path.starts_with("/tmp/")
        || path.starts_with("/var/tmp/")
        || path.starts_with("/dev/shm/")
        || path.to_lowercase().starts_with(r"c:\temp\")
        || path.to_lowercase().starts_with(r"c:\windows\temp\")
}

pub struct TemporaryFileWithStaticNameRule {
    id: RuleId,
}

impl TemporaryFileWithStaticNameRule {
    pub fn new() -> Self {
        Self {
            id: RuleId::new("python:temporary-file-with-static-name").expect("valid rule id"),
        }
    }
}

impl Default for TemporaryFileWithStaticNameRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for TemporaryFileWithStaticNameRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn applies_to(&self, lang: &LanguageIdentifier) -> bool {
        *lang == LanguageIdentifier::python()
    }

    fn default_severity(&self) -> Severity {
        Severity::Major
    }

    fn issue_type(&self) -> IssueType {
        IssueType::Vulnerability
    }

    fn remediation_effort_minutes(&self) -> u32 {
        10
    }

    fn metadata(&self) -> vord_rules_engine::RuleMetadata {
        vord_rules_engine::RuleMetadata {
            description: "A hardcoded, predictable path in a shared temp directory lets any other process on the host read, replace, or symlink-race the file first; use tempfile.mkstemp()/NamedTemporaryFile() to get a unique, privately-created name.".into(),
            tags: vec!["security".into(), "race-condition".into(), "cwe".into()],
            cwe: Some(377),
            produces_hotspots: false,
        }
    }

    fn check(&self, file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        if crate::common::is_test_file(file.path()) {
            return Vec::new();
        }
        ast.descendants()
            .filter(|n| *n.kind() == NodeKind::Call)
            .filter(|call| call.first_child().is_some_and(|callee| callee.text() == "open"))
            .filter_map(|call| {
                let args = call.children().iter().find(|c| other_kind_name(c) == Some("argument_list"))?;
                let first_arg = args.children().first()?;
                let path = literal_string_value(first_arg)?;
                looks_like_shared_temp_path(&path).then(|| Finding::new("hardcoded path in a shared temp directory is predictable and race-prone; use tempfile.mkstemp()/NamedTemporaryFile() instead", call.span()))
            })
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
        TemporaryFileWithStaticNameRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_hardcoded_tmp_path() {
        assert_eq!(findings("f = open('/tmp/upload.dat', 'wb')\n").len(), 1);
    }

    #[test]
    fn flags_hardcoded_var_tmp_path() {
        assert_eq!(findings("f = open('/var/tmp/session.lock', 'w')\n").len(), 1);
    }

    #[test]
    fn allows_tempfile_named_temporary_file() {
        assert!(findings("f = tempfile.NamedTemporaryFile()\n").is_empty());
    }

    #[test]
    fn allows_open_outside_temp_dir() {
        assert!(findings("f = open('/var/data/report.csv', 'w')\n").is_empty());
    }
}
