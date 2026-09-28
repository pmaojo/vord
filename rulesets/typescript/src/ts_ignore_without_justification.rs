//! Rule: flags a `// @ts-ignore` or `// @ts-expect-error` directive with no
//! explanation on the same line. Either directive silences a real
//! type-checker error; without a reason attached, a later reader (or the
//! original author in six months) has no way to tell whether the
//! suppressed error is still expected, already fixed, or was never
//! understood in the first place.

use vord_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use vord_rules_engine::{Finding, IssueType, Rule, RuleId, RuleMetadata, Severity};

const DIRECTIVES: [&str; 2] = ["@ts-ignore", "@ts-expect-error"];

fn missing_justification(comment: &AstNode) -> bool {
    let text = comment.text();
    let Some(rest) = text.trim_start().strip_prefix("//") else {
        return false;
    };
    let rest = rest.trim_start();
    let Some(directive) = DIRECTIVES.iter().find(|d| rest.starts_with(*d)) else {
        return false;
    };
    let after = rest[directive.len()..].trim_start_matches([':', ' ', '\t']).trim();
    after.is_empty()
}

pub struct TsIgnoreWithoutJustificationRule {
    id: RuleId,
}

impl TsIgnoreWithoutJustificationRule {
    pub fn new() -> Self {
        Self {
            id: RuleId::new("typescript:ts-ignore-without-justification").expect("valid rule id"),
        }
    }
}

impl Default for TsIgnoreWithoutJustificationRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for TsIgnoreWithoutJustificationRule {
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
        IssueType::CodeSmell
    }

    fn remediation_effort_minutes(&self) -> u32 {
        3
    }

    fn metadata(&self) -> RuleMetadata {
        RuleMetadata {
            description: "A `@ts-ignore`/`@ts-expect-error` directive with no explanation silences a type error with no record of why it's safe to ignore. Add a reason after it, e.g. `// @ts-ignore: upstream types are wrong here`.".into(),
            tags: vec!["typescript".into(), "type-safety".into(), "maintainability".into()],
            cwe: None,
            produces_hotspots: false,
        }
    }

    fn check(&self, _file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        ast.descendants()
            .filter(|n| *n.kind() == NodeKind::Comment)
            .filter(|n| missing_justification(n))
            .map(|n| {
                Finding::new(
                    "this suppression directive has no explanation; add a reason so future readers know why it's safe to ignore",
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
        TsIgnoreWithoutJustificationRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_bare_ts_ignore() {
        assert_eq!(check("// @ts-ignore\nconst x: string = 1;\n").len(), 1);
    }

    #[test]
    fn flags_bare_ts_expect_error() {
        assert_eq!(check("// @ts-expect-error\nconst x: string = 1;\n").len(), 1);
    }

    #[test]
    fn allows_ts_ignore_with_colon_reason() {
        assert!(check("// @ts-ignore: upstream types are wrong\nconst x: string = 1;\n").is_empty());
    }

    #[test]
    fn allows_ts_ignore_with_prose_reason() {
        assert!(check("// @ts-ignore this is fine because of legacy data\nconst x: string = 1;\n").is_empty());
    }

    #[test]
    fn allows_unrelated_comment() {
        assert!(check("// just a normal comment\nconst x = 1;\n").is_empty());
    }

    #[test]
    fn flags_only_the_bare_directive_among_several_comments() {
        let code = "// normal comment\n// @ts-ignore\n// @ts-ignore: reason\nconst x: string = 1;\n";
        assert_eq!(check(code).len(), 1);
    }
}
