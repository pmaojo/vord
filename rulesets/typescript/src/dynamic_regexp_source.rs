//! Rule: flags `RegExp(...)`/`new RegExp(...)` built from anything other
//! than a string literal. A regex pattern assembled from a non-literal
//! source can embed attacker-controlled regex syntax — turning ordinary
//! input into a pattern that matches unexpected things, or into a
//! catastrophically backtracking one (ReDoS) — and is exactly the shape
//! `smells:select-star`-style linters can't catch with a text scan alone.

use yunq_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use yunq_rules_engine::{Finding, IssueType, Rule, RuleId, RuleMetadata, Severity};

use crate::common::call_arguments;

fn dynamic_regexp_call(node: &AstNode) -> Option<&AstNode> {
    if *node.kind() != NodeKind::Call {
        return None;
    }
    let callee = node.first_child()?;
    if !(*callee.kind() == NodeKind::Identifier && callee.text() == "RegExp") {
        return None;
    }
    let first_arg = call_arguments(node).first()?;
    (*first_arg.kind() != NodeKind::StringLiteral).then_some(first_arg)
}

pub struct DynamicRegexpSourceRule {
    id: RuleId,
}

impl DynamicRegexpSourceRule {
    pub fn new() -> Self {
        Self { id: RuleId::new("typescript:dynamic-regexp-source").expect("valid rule id") }
    }
}

impl Default for DynamicRegexpSourceRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for DynamicRegexpSourceRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn applies_to(&self, lang: &LanguageIdentifier) -> bool {
        *lang == LanguageIdentifier::typescript()
    }

    fn default_severity(&self) -> Severity {
        Severity::Major
    }

    fn issue_type(&self) -> IssueType {
        IssueType::Vulnerability
    }

    fn metadata(&self) -> RuleMetadata {
        RuleMetadata {
            description: "Building a RegExp from a non-literal source lets attacker-controlled input inject regex syntax, changing what the pattern matches or making it catastrophically backtrack (ReDoS).".into(),
            tags: vec!["typescript".into(), "security".into(), "regex".into()],
            cwe: Some(20),
            produces_hotspots: false,
        }
    }

    fn check(&self, _file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        ast.descendants()
            .filter_map(dynamic_regexp_call)
            .map(|arg| {
                Finding::new(
                    format!("`RegExp({})` is built from a non-literal source; if it can carry external input, it can inject regex syntax or cause catastrophic backtracking", arg.text()),
                    arg.span(),
                )
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use yunq_ast::SourceFile;
    use yunq_rules_engine::AstParser;

    use super::*;

    fn check(code: &str) -> Vec<Finding> {
        let file = SourceFile::new("t.ts", code, LanguageIdentifier::typescript()).unwrap();
        let ast = yunq_parser_typescript::TypeScriptParser::new().parse(&file).unwrap();
        DynamicRegexpSourceRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_new_regexp_with_variable_source() {
        assert_eq!(check("new RegExp(userInput);\n").len(), 1);
    }

    #[test]
    fn flags_regexp_call_without_new() {
        assert_eq!(check("RegExp(pattern);\n").len(), 1);
    }

    #[test]
    fn allows_string_literal_source() {
        assert!(check("new RegExp('^[a-z]+$');\n").is_empty());
    }

    #[test]
    fn allows_regex_literal() {
        assert!(check("const r = /^[a-z]+$/;\n").is_empty());
    }
}
