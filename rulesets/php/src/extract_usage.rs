use vord_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use vord_rules_engine::{Finding, IssueType, Rule, RuleId, Severity};

use crate::common::callee_node;

/// Security hotspot: `extract()` imports every key of an array into the
/// current symbol table as a variable — called on request data
/// (`$_GET`/`$_POST`/`$_REQUEST`/a merge of them), an attacker picks the
/// array keys and therefore picks which variables in the calling scope get
/// overwritten, and with what values. That's a variable-injection
/// vulnerability, not just a style nit: it can silently clobber a variable
/// the rest of the function assumed only it could set (an auth flag, a
/// role, a computed total).
pub struct ExtractUsageRule {
    id: RuleId,
}

impl ExtractUsageRule {
    pub fn new() -> Self {
        Self {
            id: RuleId::new("php:extract-usage").expect("valid rule id"),
        }
    }
}

impl Default for ExtractUsageRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for ExtractUsageRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn applies_to(&self, language: &LanguageIdentifier) -> bool {
        *language == LanguageIdentifier::php()
    }

    fn default_severity(&self) -> Severity {
        Severity::Critical
    }

    fn issue_type(&self) -> IssueType {
        IssueType::Vulnerability
    }

    fn remediation_effort_minutes(&self) -> u32 {
        20
    }

    fn metadata(&self) -> vord_rules_engine::RuleMetadata {
        vord_rules_engine::RuleMetadata {
            description: "`extract()` imports every key of its array argument as a variable in \
                the current scope; if the array can contain attacker-chosen keys (request \
                data), the attacker chooses which local variables get overwritten. Read the \
                specific keys you need instead of extracting the whole array."
                .into(),
            tags: vec!["security".into(), "injection".into(), "php".into()],
            cwe: Some(915),
            produces_hotspots: true,
        }
    }

    fn check(&self, _file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        ast.descendants()
            .filter(|n| *n.kind() == NodeKind::Call)
            .filter(|call| {
                callee_node(call)
                    .is_some_and(|c| *c.kind() == NodeKind::Identifier && c.text() == "extract")
            })
            .map(|call| {
                Finding::hotspot(
                    "confirm the array passed to `extract()` can never contain \
                    attacker-chosen keys",
                    call.span(),
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
        let file = SourceFile::new("t.php", code, LanguageIdentifier::php()).unwrap();
        let ast = vord_parser_php::PhpParser::new().parse(&file).unwrap();
        ExtractUsageRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_extract_of_superglobal() {
        assert_eq!(check("<?php\nextract($_GET);\n").len(), 1);
    }

    #[test]
    fn flags_extract_of_local_array_too() {
        // Same syntactic risk regardless of the array's declared origin —
        // no type/flow resolution is attempted here.
        assert_eq!(check("<?php\nextract($config);\n").len(), 1);
    }

    #[test]
    fn ignores_unrelated_calls() {
        assert!(check("<?php\ncompact('a', 'b');\n").is_empty());
    }
}
