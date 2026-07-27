//! Rule: flags `from module import *`. It dumps every public name from
//! the target module into the current namespace, silently shadowing
//! local names and making it impossible to tell where an identifier
//! came from just by reading the file.

use yunq_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use yunq_rules_engine::{Finding, Rule, RuleId, Severity};

fn other_kind_name(node: &AstNode) -> Option<&str> {
    match node.kind() {
        NodeKind::Other(name) => Some(name.as_ref()),
        _ => None,
    }
}

pub struct WildcardImportRule {
    id: RuleId,
}

impl WildcardImportRule {
    pub fn new() -> Self {
        Self { id: RuleId::new("python:wildcard-import").expect("valid rule id") }
    }
}

impl Default for WildcardImportRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for WildcardImportRule {
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
        10
    }

    fn metadata(&self) -> yunq_rules_engine::RuleMetadata {
        yunq_rules_engine::RuleMetadata {
            description: "`from module import *` pulls every public name into this file's namespace, shadowing local names unpredictably and hiding where each identifier is actually defined; import the specific names you need instead.".into(),
            tags: vec!["maintainability".into(), "python-idiom".into()],
            cwe: None,
            produces_hotspots: false,
        }
    }

    fn check(&self, _file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        ast.descendants()
            .filter(|n| other_kind_name(n) == Some("import_from_statement"))
            .filter(|n| n.children().iter().any(|c| other_kind_name(c) == Some("wildcard_import")))
            .map(|n| Finding::new("wildcard import pulls every public name into this namespace; import the specific names you need", n.span()))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use yunq_rules_engine::AstParser;

    use super::*;

    fn findings(code: &str) -> Vec<Finding> {
        let file = SourceFile::new("t.py", code, LanguageIdentifier::python()).unwrap();
        let ast = yunq_parser_python::PythonParser::new().parse(&file).unwrap();
        WildcardImportRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_wildcard_import() {
        assert_eq!(findings("from os import *\n").len(), 1);
    }

    #[test]
    fn allows_named_import() {
        assert!(findings("from os import path, getenv\n").is_empty());
    }
}
