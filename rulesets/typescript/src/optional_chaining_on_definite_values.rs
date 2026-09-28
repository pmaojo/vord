//! Rule: flags `?.` used directly on `this` (`this?.foo`) or directly on a
//! freshly-constructed value (`new Foo()?.bar`). In both cases the operand
//! can never be `null`/`undefined` at that point — `this` inside a normal
//! method call is never nullish, and a `new` expression always produces an
//! object — so the optional chain silences a null check that can never
//! actually trigger, usually masking a mistake elsewhere rather than
//! guarding anything real.

use vord_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use vord_rules_engine::{Finding, IssueType, Rule, RuleId, RuleMetadata, Severity};

use crate::common::is_other;

fn is_new_call(node: &AstNode) -> bool {
    *node.kind() == NodeKind::Call && node.text().trim_start().starts_with("new ")
}

fn flagged(member: &AstNode) -> bool {
    if *member.kind() != NodeKind::MemberAccess {
        return false;
    }
    if !member.children().iter().any(|c| is_other(c, "optional_chain")) {
        return false;
    }
    let Some(object) = member.first_child() else {
        return false;
    };
    is_other(object, "this") || is_new_call(object)
}

pub struct OptionalChainingOnDefiniteValuesRule {
    id: RuleId,
}

impl OptionalChainingOnDefiniteValuesRule {
    pub fn new() -> Self {
        Self {
            id: RuleId::new("typescript:optional-chaining-on-definite-values")
                .expect("valid rule id"),
        }
    }
}

impl Default for OptionalChainingOnDefiniteValuesRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for OptionalChainingOnDefiniteValuesRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn applies_to(&self, lang: &LanguageIdentifier) -> bool {
        *lang == LanguageIdentifier::typescript()
    }

    fn default_severity(&self) -> Severity {
        Severity::Info
    }

    fn issue_type(&self) -> IssueType {
        IssueType::CodeSmell
    }

    fn remediation_effort_minutes(&self) -> u32 {
        2
    }

    fn metadata(&self) -> RuleMetadata {
        RuleMetadata {
            description: "`?.` here guards against a value (`this`, or a freshly-constructed `new` expression) that can never be null/undefined at this point, so the check can never trigger. Use a plain `.` — an optional chain that never fires usually masks a real mistake instead of guarding anything.".into(),
            tags: vec!["typescript".into(), "clarity".into()],
            cwe: None,
            produces_hotspots: false,
        }
    }

    fn check(&self, _file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        ast.descendants()
            .filter(|n| flagged(n))
            .map(|n| {
                Finding::new(
                    "this `?.` guards a value that can never be null/undefined here; use a plain `.`",
                    n.span(),
                )
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
        let file = SourceFile::new("t.ts", code, LanguageIdentifier::typescript()).unwrap();
        let ast = vord_parser_typescript::TypeScriptParser::new()
            .parse(&file)
            .unwrap();
        OptionalChainingOnDefiniteValuesRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_optional_chain_on_this() {
        assert_eq!(check("class C {\n  m() {\n    return this?.value;\n  }\n}\n").len(), 1);
    }

    #[test]
    fn flags_optional_chain_on_new_expression() {
        assert_eq!(check("const v = new Foo()?.bar;\n").len(), 1);
    }

    #[test]
    fn allows_optional_chain_on_a_regular_identifier() {
        assert!(check("const v = a?.b;\n").is_empty());
    }

    #[test]
    fn allows_plain_member_access_on_this() {
        assert!(check("class C {\n  m() {\n    return this.value;\n  }\n}\n").is_empty());
    }

    #[test]
    fn allows_optional_chain_on_a_function_call_result() {
        assert!(check("const v = getFoo()?.bar;\n").is_empty());
    }
}
