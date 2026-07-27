//! Rule: flags `var` in favor of `let`/`const`. `var` is function-scoped
//! (not block-scoped) and hoisted with no temporal-dead-zone protection, so
//! it silently survives outside the block it looks like it belongs to and
//! can be read before its declaration runs — `let`/`const` closes both
//! holes. tree-sitter-typescript already tells `var` apart from `let`/
//! `const` at the grammar level: only `var` produces a `variable_declaration`
//! node; `let`/`const` produce `lexical_declaration`.

use yunq_ast::{AstNode, LanguageIdentifier, SourceFile};
use yunq_rules_engine::{Finding, IssueType, Rule, RuleId, RuleMetadata, Severity};

use crate::common::is_other;

pub struct VarDeclarationRule {
    id: RuleId,
}

impl VarDeclarationRule {
    pub fn new() -> Self {
        Self { id: RuleId::new("typescript:var-declaration").expect("valid rule id") }
    }
}

impl Default for VarDeclarationRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for VarDeclarationRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn applies_to(&self, lang: &LanguageIdentifier) -> bool {
        *lang == LanguageIdentifier::typescript()
    }

    fn default_severity(&self) -> Severity {
        Severity::Minor
    }

    fn issue_type(&self) -> IssueType {
        IssueType::CodeSmell
    }

    fn remediation_effort_minutes(&self) -> u32 {
        2
    }

    fn metadata(&self) -> RuleMetadata {
        RuleMetadata {
            description: "`var` is function-scoped and hoisted with no temporal-dead-zone protection, unlike block-scoped `let`/`const`; prefer `let`/`const`.".into(),
            tags: vec!["typescript".into(), "pitfall".into()],
            cwe: None,
            produces_hotspots: false,
        }
    }

    fn check(&self, _file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        ast.descendants()
            .filter(|n| is_other(n, "variable_declaration"))
            .map(|n| Finding::new("`var` is function-scoped and hoisted; use `let` or `const` instead", n.span()))
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
        VarDeclarationRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_var() {
        let findings = check("var x = 1;\n");
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn allows_let_and_const() {
        assert!(check("let y = 2;\nconst z = 3;\n").is_empty());
    }
}
