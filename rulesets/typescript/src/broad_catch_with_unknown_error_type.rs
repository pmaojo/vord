//! Rule: flags a `catch` block that reads `.message`, `.stack`, or `.name`
//! off the caught value with no `instanceof`/`typeof` narrowing anywhere in
//! the block first. A caught value is typed `unknown` (or implicitly `any`)
//! — nothing guarantees it is an `Error`, so accessing error-shaped
//! properties without narrowing first can throw at runtime on a
//! non-`Error` throw (`throw "boom"`, `throw { code: 1 }`, ...).

use vord_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use vord_rules_engine::{Finding, IssueType, Rule, RuleId, RuleMetadata, Severity};

use crate::common::is_other;

const ERROR_LIKE_PROPS: [&str; 3] = ["message", "stack", "name"];

fn is_narrowed(block: &AstNode) -> bool {
    let text = block.text();
    text.contains("instanceof") || text.contains("typeof")
}

fn unguarded_access<'a>(block: &'a AstNode, param_name: &str) -> Option<&'a AstNode> {
    if is_narrowed(block) {
        return None;
    }
    block.descendants().find(|n| {
        *n.kind() == NodeKind::MemberAccess
            && n.first_child().is_some_and(|obj| obj.text() == param_name)
            && n.children()
                .last()
                .is_some_and(|prop| ERROR_LIKE_PROPS.contains(&prop.text()))
    })
}

fn flagged(catch_clause: &AstNode) -> Option<&AstNode> {
    let param = catch_clause.first_child()?;
    if *param.kind() != NodeKind::Identifier {
        return None;
    }
    let block = catch_clause
        .children()
        .iter()
        .find(|c| is_other(c, "statement_block"))?;
    unguarded_access(block, param.text())
}

pub struct BroadCatchWithUnknownErrorTypeRule {
    id: RuleId,
}

impl BroadCatchWithUnknownErrorTypeRule {
    pub fn new() -> Self {
        Self {
            id: RuleId::new("typescript:broad-catch-with-unknown-error-type")
                .expect("valid rule id"),
        }
    }
}

impl Default for BroadCatchWithUnknownErrorTypeRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for BroadCatchWithUnknownErrorTypeRule {
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

    fn remediation_effort_minutes(&self) -> u32 {
        10
    }

    fn metadata(&self) -> RuleMetadata {
        RuleMetadata {
            description: "The caught value's type is unknown (nothing guarantees a thrown value is an `Error`); accessing `.message`/`.stack`/`.name` without an `instanceof Error` or `typeof` check first can throw on a non-Error throw.".into(),
            tags: vec!["typescript".into(), "reliability".into(), "error-handling".into()],
            cwe: Some(704),
            produces_hotspots: false,
        }
    }

    fn check(&self, _file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        ast.descendants()
            .filter(|n| is_other(n, "catch_clause"))
            .filter_map(flagged)
            .map(|n| {
                Finding::new(
                    "this reads an error property off the caught value with no `instanceof`/`typeof` narrowing first; the caught value's real type is not guaranteed to be `Error`",
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
        BroadCatchWithUnknownErrorTypeRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_message_access_without_narrowing() {
        let code = "try {\n  doWork();\n} catch (e) {\n  console.log(e.message);\n}\n";
        assert_eq!(check(code).len(), 1);
    }

    #[test]
    fn flags_stack_access_without_narrowing() {
        let code = "try {\n  doWork();\n} catch (err) {\n  log(err.stack);\n}\n";
        assert_eq!(check(code).len(), 1);
    }

    #[test]
    fn allows_access_after_instanceof_check() {
        let code = "try {\n  doWork();\n} catch (e) {\n  if (e instanceof Error) {\n    console.log(e.message);\n  }\n}\n";
        assert!(check(code).is_empty());
    }

    #[test]
    fn allows_access_after_typeof_check() {
        let code = "try {\n  doWork();\n} catch (e) {\n  if (typeof e === 'object') {\n    console.log(e.message);\n  }\n}\n";
        assert!(check(code).is_empty());
    }

    #[test]
    fn allows_catch_that_does_not_touch_error_props() {
        let code = "try {\n  doWork();\n} catch (e) {\n  logFailure();\n}\n";
        assert!(check(code).is_empty());
    }

    #[test]
    fn allows_catch_with_no_binding() {
        assert!(check("try {\n  doWork();\n} catch {\n  handle();\n}\n").is_empty());
    }
}
