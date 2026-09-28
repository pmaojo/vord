//! Rule: flags an `interface` whose set of `name: type` property signatures
//! is identical (order aside) to another interface's in the same file.
//! Two interfaces with the same members are either the same concept
//! declared twice under different names, or a sign one should extend (or
//! alias) the other — this analyzer only compares the literal declared
//! text of each interface's own property signatures, not full structural
//! typing, so it can miss duplicates hidden behind inherited members or
//! type aliases.

use vord_ast::{AstNode, LanguageIdentifier, SourceFile};
use vord_rules_engine::{Finding, IssueType, Rule, RuleId, RuleMetadata, Severity};

use crate::common::is_other;

/// A sorted `"name:type"` fingerprint of an interface's own property
/// signatures. `None` when the interface isn't a plain data shape (extends
/// another type, or declares anything besides `property_signature`), since
/// comparing those textually would be unreliable.
fn fingerprint(decl: &AstNode) -> Option<Vec<String>> {
    if decl.children().iter().any(|c| is_other(c, "extends_type_clause")) {
        return None;
    }
    let body = decl.children().iter().find(|c| is_other(c, "interface_body"))?;
    if body.children().is_empty() {
        return None;
    }
    if !body.children().iter().all(|c| is_other(c, "property_signature")) {
        return None;
    }
    let mut members: Vec<String> = body
        .children()
        .iter()
        .map(|prop| prop.text().split_whitespace().collect::<String>())
        .collect();
    members.sort();
    Some(members)
}

pub struct InterfaceDuplicatedStructureRule {
    id: RuleId,
}

impl InterfaceDuplicatedStructureRule {
    pub fn new() -> Self {
        Self {
            id: RuleId::new("typescript:interface-duplicated-structure").expect("valid rule id"),
        }
    }
}

impl Default for InterfaceDuplicatedStructureRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for InterfaceDuplicatedStructureRule {
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
        15
    }

    fn metadata(&self) -> RuleMetadata {
        RuleMetadata {
            description: "This interface declares exactly the same properties as another interface in this file. Merge them, or have one extend the other, instead of maintaining two copies of the same shape.".into(),
            tags: vec!["typescript".into(), "duplication".into(), "maintainability".into()],
            cwe: None,
            produces_hotspots: false,
        }
    }

    fn check(&self, _file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        let interfaces: Vec<&AstNode> = ast
            .descendants()
            .filter(|n| is_other(n, "interface_declaration"))
            .collect();
        let fingerprints: Vec<Option<Vec<String>>> =
            interfaces.iter().map(|n| fingerprint(n)).collect();

        let mut findings = Vec::new();
        for (i, fp) in fingerprints.iter().enumerate() {
            let Some(fp) = fp else { continue };
            let duplicated = fingerprints
                .iter()
                .enumerate()
                .any(|(j, other)| j != i && other.as_ref() == Some(fp));
            if duplicated {
                findings.push(Finding::new(
                    "this interface declares the same properties as another interface in this file; merge them or have one extend the other",
                    interfaces[i].span(),
                ));
            }
        }
        findings
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
        InterfaceDuplicatedStructureRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_two_interfaces_with_identical_properties_in_any_order() {
        let code = "interface A { x: number; y: string; }\ninterface B { y: string; x: number; }\n";
        assert_eq!(check(code).len(), 2);
    }

    #[test]
    fn allows_interfaces_with_different_properties() {
        let code = "interface A { x: number; }\ninterface B { y: string; }\n";
        assert!(check(code).is_empty());
    }

    #[test]
    fn allows_single_interface() {
        assert!(check("interface A { x: number; }\n").is_empty());
    }

    #[test]
    fn allows_extending_interface_even_if_similar() {
        let code = "interface Base { x: number; }\ninterface A extends Base { y: string; }\ninterface B { x: number; y: string; }\n";
        assert!(check(code).is_empty());
    }

    #[test]
    fn allows_interface_with_methods() {
        let code = "interface A { x: number; run(): void; }\ninterface B { x: number; run(): void; }\n";
        assert!(check(code).is_empty());
    }
}
