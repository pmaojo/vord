//! Rule: flags `open(path)` in text mode with no explicit `encoding=`.
//! Without one, Python uses the platform's locale-preferred encoding —
//! `utf-8` on most Linux/macOS setups but `cp1252` or similar on Windows
//! — so the same code can read a file correctly in CI and mangle it (or
//! raise `UnicodeDecodeError`) for a user on a different platform.

use yunq_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use yunq_rules_engine::{Finding, Rule, RuleId, Severity};

fn other_kind_name(node: &AstNode) -> Option<&str> {
    match node.kind() {
        NodeKind::Other(name) => Some(name.as_ref()),
        _ => None,
    }
}

fn string_content(node: &AstNode) -> Option<String> {
    if *node.kind() != NodeKind::StringLiteral {
        return None;
    }
    Some(
        node.children()
            .iter()
            .filter(|c| other_kind_name(c) == Some("string_content"))
            .map(|c| c.text())
            .collect(),
    )
}

fn is_binary_mode(mode_value: &AstNode) -> bool {
    string_content(mode_value).is_some_and(|content| content.contains('b'))
}

fn opens_in_binary_mode(args: &[AstNode]) -> bool {
    let positional: Vec<&AstNode> = args
        .iter()
        .filter(|a| other_kind_name(a) != Some("keyword_argument"))
        .collect();
    if positional.get(1).is_some_and(|mode| is_binary_mode(mode)) {
        return true;
    }
    args.iter().any(|arg| {
        other_kind_name(arg) == Some("keyword_argument")
            && arg
                .children()
                .first()
                .is_some_and(|name| name.text() == "mode")
            && arg.children().get(1).is_some_and(is_binary_mode)
    })
}

fn has_encoding_argument(args: &[AstNode]) -> bool {
    args.iter().any(|arg| {
        other_kind_name(arg) == Some("keyword_argument")
            && arg
                .children()
                .first()
                .is_some_and(|name| name.text() == "encoding")
    })
}

pub struct OpenWithoutEncodingRule {
    id: RuleId,
}

impl OpenWithoutEncodingRule {
    pub fn new() -> Self {
        Self {
            id: RuleId::new("python:open-without-encoding").expect("valid rule id"),
        }
    }
}

impl Default for OpenWithoutEncodingRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for OpenWithoutEncodingRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn applies_to(&self, lang: &LanguageIdentifier) -> bool {
        *lang == LanguageIdentifier::python()
    }

    fn default_severity(&self) -> Severity {
        Severity::Minor
    }

    fn remediation_effort_minutes(&self) -> u32 {
        5
    }

    fn metadata(&self) -> yunq_rules_engine::RuleMetadata {
        yunq_rules_engine::RuleMetadata {
            description: "open() in text mode with no explicit encoding uses the platform's locale-preferred encoding, which differs between systems; pass encoding='utf-8' (or whatever the file actually is) so reading it is reproducible everywhere.".into(),
            tags: vec!["reliability".into(), "python-idiom".into()],
            cwe: None,
            produces_hotspots: false,
        }
    }

    fn check(&self, file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        if yunq_rules_engine::is_test_only_path(file.path()) {
            return Vec::new();
        }
        ast.descendants()
            .filter(|n| *n.kind() == NodeKind::Call)
            .filter(|call| call.first_child().is_some_and(|callee| callee.kind() == &NodeKind::Identifier && callee.text() == "open"))
            .filter_map(|call| {
                let args = call.children().iter().find(|c| other_kind_name(c) == Some("argument_list"))?;
                let args = args.children();
                (!opens_in_binary_mode(args) && !has_encoding_argument(args))
                    .then(|| Finding::new("open() in text mode with no explicit encoding depends on the platform's default encoding; pass encoding= explicitly", call.span()))
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use yunq_rules_engine::AstParser;

    use super::*;

    fn findings(code: &str) -> Vec<Finding> {
        let file = SourceFile::new("t.py", code, LanguageIdentifier::python()).unwrap();
        let ast = yunq_parser_python::PythonParser::new()
            .parse(&file)
            .unwrap();
        OpenWithoutEncodingRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_text_mode_open_without_encoding() {
        assert_eq!(findings("f = open('x.txt')\n").len(), 1);
    }

    #[test]
    fn allows_explicit_encoding() {
        assert!(findings("f = open('x.txt', encoding='utf-8')\n").is_empty());
    }

    #[test]
    fn allows_binary_mode_without_encoding() {
        assert!(findings("f = open('x.bin', 'rb')\n").is_empty());
    }
}
