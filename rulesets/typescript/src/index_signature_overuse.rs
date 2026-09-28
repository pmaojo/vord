//! Rule: flags an `interface`/object type that mixes an index signature
//! (`[key: string]: T`) with named, explicitly-typed properties. An index
//! signature says "any string key maps to `T`", which already permits (and
//! silently types) every named property below it — mixing the two usually
//! means the shape should either be tightened to just the named properties,
//! or the named properties dropped in favor of the general index.

use vord_ast::{AstNode, LanguageIdentifier, SourceFile};
use vord_rules_engine::{Finding, IssueType, Rule, RuleId, RuleMetadata, Severity};

use crate::common::is_other;

fn is_body(node: &AstNode) -> bool {
    is_other(node, "interface_body") || is_other(node, "object_type")
}

fn flagged(body: &AstNode) -> bool {
    let has_index = body.children().iter().any(|c| is_other(c, "index_signature"));
    let has_property = body
        .children()
        .iter()
        .any(|c| is_other(c, "property_signature"));
    has_index && has_property
}

pub struct IndexSignatureOveruseRule {
    id: RuleId,
}

impl IndexSignatureOveruseRule {
    pub fn new() -> Self {
        Self {
            id: RuleId::new("typescript:index-signature-overuse").expect("valid rule id"),
        }
    }
}

impl Default for IndexSignatureOveruseRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for IndexSignatureOveruseRule {
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
        10
    }

    fn metadata(&self) -> RuleMetadata {
        RuleMetadata {
            description: "This type mixes an index signature with explicit named properties. The index signature already types every string key (including the named ones); tighten the shape to just the named properties, or drop them in favor of the general index.".into(),
            tags: vec!["typescript".into(), "type-safety".into(), "clarity".into()],
            cwe: None,
            produces_hotspots: false,
        }
    }

    fn check(&self, _file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        ast.descendants()
            .filter(|n| is_body(n))
            .filter(|n| flagged(n))
            .map(|n| {
                Finding::new(
                    "this type mixes an index signature with named properties; tighten to one or the other",
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
        IndexSignatureOveruseRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_interface_mixing_index_and_property() {
        let code = "interface Foo {\n  [key: string]: number;\n  a: number;\n}\n";
        assert_eq!(check(code).len(), 1);
    }

    #[test]
    fn flags_object_type_alias_mixing_index_and_property() {
        let code = "type Foo = { [key: string]: number; a: number };\n";
        assert_eq!(check(code).len(), 1);
    }

    #[test]
    fn allows_index_signature_alone() {
        assert!(check("interface Foo {\n  [key: string]: number;\n}\n").is_empty());
    }

    #[test]
    fn allows_named_properties_alone() {
        assert!(check("interface Foo {\n  a: number;\n  b: string;\n}\n").is_empty());
    }
}
