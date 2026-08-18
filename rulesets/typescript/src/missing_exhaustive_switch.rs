//! Rule: flags a `switch` statement with no `default` case. Without a
//! default clause (or a type-checker-verified exhaustive set of cases), an
//! unhandled value silently falls through with no branch running — the
//! classic motivation for ESLint's `default-case` /
//! `@typescript-eslint/switch-exhaustiveness-check`. This crate has no
//! type-checker access to confirm every union member is actually covered,
//! so the syntactic proxy used here is simpler and more reliable: require a
//! `default:` case to exist at all.

use vord_ast::{AstNode, LanguageIdentifier, SourceFile};
use vord_rules_engine::{Finding, IssueType, Rule, RuleId, RuleMetadata, Severity};

use crate::common::is_other;

fn missing_default(switch_stmt: &AstNode) -> bool {
    let Some(body) = switch_stmt.children().iter().find(|c| is_other(c, "switch_body")) else {
        return false;
    };
    !body.children().iter().any(|c| is_other(c, "switch_default"))
}

pub struct MissingExhaustiveSwitchRule {
    id: RuleId,
}

impl MissingExhaustiveSwitchRule {
    pub fn new() -> Self {
        Self {
            id: RuleId::new("typescript:missing-exhaustive-switch").expect("valid rule id"),
        }
    }
}

impl Default for MissingExhaustiveSwitchRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for MissingExhaustiveSwitchRule {
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
        5
    }

    fn metadata(&self) -> RuleMetadata {
        RuleMetadata {
            description: "A `switch` with no `default` case silently does nothing for any value not explicitly handled. Add a `default:` (even just to throw on an unexpected case) or verify exhaustiveness some other way.".into(),
            tags: vec!["typescript".into(), "reliability".into()],
            cwe: Some(478),
            produces_hotspots: false,
        }
    }

    fn check(&self, _file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        ast.descendants()
            .filter(|n| is_other(n, "switch_statement"))
            .filter(|n| missing_default(n))
            .map(|n| {
                Finding::new(
                    "this `switch` has no `default` case; add one to handle unexpected values explicitly",
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
        MissingExhaustiveSwitchRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_switch_without_default() {
        let findings = check("switch (x) {\n case 1: break;\n case 2: break;\n}\n");
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn allows_switch_with_default() {
        assert!(check("switch (x) {\n case 1: break;\n default: break;\n}\n").is_empty());
    }

    #[test]
    fn allows_switch_with_default_first() {
        assert!(check("switch (x) {\n default: doIt(); break;\n case 1: break;\n}\n").is_empty());
    }

    #[test]
    fn flags_each_switch_independently() {
        let code = "switch (x) {\n case 1: break;\n}\nswitch (y) {\n case 2: break;\n}\n";
        assert_eq!(check(code).len(), 2);
    }
}
