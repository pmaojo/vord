//! Rule: flags `JSON.parse(x)` where `x` isn't a string literal (so its
//! content is unknown at analysis time) and the call isn't inside a `try`
//! block anywhere in its enclosing scope. Malformed JSON makes `JSON.parse`
//! throw a `SyntaxError` synchronously; with no `try`/`catch` around it,
//! that exception propagates uncaught. A literal string argument is
//! exempted — its content is fixed at the call site, so parsing it can only
//! ever fail the same deterministic way, which is a bug to fix, not a
//! runtime condition to guard against.

use yunq_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use yunq_rules_engine::{Finding, IssueType, Rule, RuleId, RuleMetadata, Severity};

use crate::common::{call_arguments, is_other};

fn is_unguarded_json_parse(node: &AstNode) -> bool {
    if *node.kind() != NodeKind::Call {
        return false;
    }
    let Some(callee) = node.first_child() else {
        return false;
    };
    if callee.text() != "JSON.parse" {
        return false;
    }
    call_arguments(node)
        .first()
        .is_some_and(|arg| *arg.kind() != NodeKind::StringLiteral)
}

/// Recursive descent tracking whether the current node lies inside a
/// `try_statement`'s try-block: tree-sitter-typescript's `try_statement`
/// has the try block as its first named child, with an optional
/// `catch_clause`/`finally_clause` after it — those are new scopes with
/// their own protection (or lack of it), not "inside the try" themselves.
fn collect<'a>(node: &'a AstNode, in_try: bool, out: &mut Vec<&'a AstNode>) {
    if is_unguarded_json_parse(node) && !in_try {
        out.push(node);
    }
    if is_other(node, "try_statement") {
        for (i, child) in node.children().iter().enumerate() {
            collect(child, i == 0, out);
        }
        return;
    }
    for child in node.children() {
        collect(child, in_try, out);
    }
}

pub struct JsonParseUnguardedRule {
    id: RuleId,
}

impl JsonParseUnguardedRule {
    pub fn new() -> Self {
        Self {
            id: RuleId::new("typescript:json-parse-unguarded").expect("valid rule id"),
        }
    }
}

impl Default for JsonParseUnguardedRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for JsonParseUnguardedRule {
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
        IssueType::Bug
    }

    fn metadata(&self) -> RuleMetadata {
        RuleMetadata {
            description: "`JSON.parse` throws a SyntaxError on malformed input; parsing a non-literal (potentially external) value with no enclosing `try`/`catch` lets that exception propagate uncaught.".into(),
            tags: vec!["typescript".into(), "reliability".into()],
            cwe: Some(248),
            produces_hotspots: false,
        }
    }

    fn check(&self, _file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        let mut out = Vec::new();
        collect(ast, false, &mut out);
        out.into_iter()
            .map(|n| Finding::new("`JSON.parse` of a non-literal value with no enclosing try/catch throws uncaught on malformed input", n.span()))
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
        let ast = yunq_parser_typescript::TypeScriptParser::new()
            .parse(&file)
            .unwrap();
        JsonParseUnguardedRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_unguarded_dynamic_parse() {
        assert_eq!(check("const x = JSON.parse(data);\n").len(), 1);
    }

    #[test]
    fn allows_parse_inside_try() {
        assert!(check("try {\n  const x = JSON.parse(data);\n} catch (e) {}\n").is_empty());
    }

    #[test]
    fn flags_parse_inside_catch_block() {
        assert_eq!(
            check("try {\n  f();\n} catch (e) {\n  const x = JSON.parse(fallback);\n}\n").len(),
            1
        );
    }

    #[test]
    fn allows_string_literal_argument() {
        assert!(check("const x = JSON.parse('{\"a\":1}');\n").is_empty());
    }
}
