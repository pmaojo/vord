//! Rule: flags `context.WithValue(ctx, "someKey", value)` where the key is
//! a bare string literal. Two unrelated packages each doing this with the
//! same string ("requestID", "userID", ...) silently collide and overwrite
//! each other's value with no compile-time or runtime signal — the
//! motivating example in both the Go blog's own context guidance and
//! staticcheck's `SA1029` ("should not use built-in type string as key for
//! value; define your own type to avoid collisions"), which this rule
//! mirrors. Define an unexported key type instead (`type ctxKey int` or
//! similar) so the compiler enforces uniqueness.

use vord_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use vord_rules_engine::{
    Finding, IssueType, Rule, RuleId, RuleMetadata, Severity, declare_rule_id,
};

use crate::common::{arguments, callee};

fn is_context_with_value(call: &AstNode) -> bool {
    callee(call).is_some_and(|c| c.text() == "context.WithValue")
}

declare_rule_id!(ContextValueStringKeyRule, "go:context-value-string-key");

impl Rule for ContextValueStringKeyRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn applies_to(&self, language: &LanguageIdentifier) -> bool {
        *language == LanguageIdentifier::go()
    }

    fn default_severity(&self) -> Severity {
        Severity::Major
    }

    fn issue_type(&self) -> IssueType {
        IssueType::Bug
    }

    fn metadata(&self) -> RuleMetadata {
        RuleMetadata {
            description: "A bare string literal as a `context.WithValue` key can collide with \
                an identically-named key from an unrelated package, silently overwriting its \
                value with no signal at compile time or runtime. Define an unexported key type \
                (e.g. `type ctxKey int`) instead."
                .into(),
            tags: vec!["go".into(), "correctness".into()],
            cwe: None,
            produces_hotspots: false,
        }
    }

    fn check(&self, _file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        ast.descendants()
            .filter(|n| *n.kind() == NodeKind::Call && is_context_with_value(n))
            .filter_map(|call| {
                let key = arguments(call)?.get(1)?;
                (*key.kind() == NodeKind::StringLiteral).then(|| {
                    Finding::new(
                        "context key is a bare string literal; define an unexported key type \
                        instead to avoid collisions with an unrelated package's identically-named \
                        key"
                        .to_string(),
                        call.span(),
                    )
                })
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use vord_ast::SourceFile;
    use vord_rules_engine::AstParser;

    use super::*;

    fn check(code: &str) -> Vec<Finding> {
        let file = SourceFile::new("t.go", code, LanguageIdentifier::go()).unwrap();
        let ast = vord_parser_go::GoParser::new().parse(&file).unwrap();
        ContextValueStringKeyRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_string_literal_key() {
        assert_eq!(
            check("package main\nfunc f(ctx context.Context) {\n\tctx = context.WithValue(ctx, \"userID\", 1)\n}\n")
                .len(),
            1
        );
    }

    #[test]
    fn allows_typed_key() {
        assert!(check(
            "package main\nfunc f(ctx context.Context) {\n\tctx = context.WithValue(ctx, userIDKey, 1)\n}\n"
        )
        .is_empty());
    }

    #[test]
    fn ignores_unrelated_calls() {
        assert!(check("package main\nfunc f() {\n\tfmt.Println(\"userID\", 1)\n}\n").is_empty());
    }
}
