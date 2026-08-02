//! Rule: a method that reaches into another class's members far more than
//! its own — the classic "Feature Envy" smell (the method seems more
//! interested in a different class than the one it's defined on, and
//! probably belongs there instead). This is the rule the symbol table
//! exists for: telling "a member access on a parameter whose type is some
//! *other known class*" apart from "a member access on anything else"
//! needs the declared-type resolution `vord_symbols` provides — a plain
//! AST-shape rule can't tell a foreign-class access from an access on an
//! unrelated plain object or a primitive-typed parameter.
//!
//! Whole-program (`CrossFileRule`): built via `ClassRegistry::build_cross_file`
//! so a parameter typed as a class declared in another file still resolves —
//! same wiring pattern as `smells:god-class`.

use std::collections::HashMap;

use vord_ast::{AstNode, NodeKind, SourceFile};
use vord_rules_engine::{CrossFileRule, Finding, IssueType, RuleId, RuleMetadata, Severity};
use vord_symbols::ClassRegistry;

/// Member accesses on `self`/`this` (own-class access) and on `base_name`
/// (a specific foreign-typed parameter), counted in one pass over the
/// method body.
fn count_accesses(body: &AstNode, base_name: &str) -> (usize, usize) {
    let mut own = 0usize;
    let mut foreign = 0usize;
    for access in body
        .descendants()
        .filter(|n| *n.kind() == NodeKind::MemberAccess)
    {
        let Some(base) = access.first_child() else {
            continue;
        };
        // Only a direct `name.field` counts, not a chain's outer link
        // (`a.b.c`'s outer access has `a.b` as its base, not a plain name) —
        // avoids double-counting one physical access as two.
        if *base.kind() != NodeKind::Identifier && base.text() != "self" && base.text() != "this" {
            continue;
        }
        match base.text() {
            "self" | "this" => own += 1,
            name if name == base_name => foreign += 1,
            _ => {}
        }
    }
    (own, foreign)
}

pub struct FeatureEnvyRule {
    id: RuleId,
    min_foreign_accesses: usize,
}

impl FeatureEnvyRule {
    pub fn new(min_foreign_accesses: usize) -> Self {
        Self {
            id: RuleId::new("smells:feature-envy").expect("valid rule id"),
            min_foreign_accesses,
        }
    }
}

impl Default for FeatureEnvyRule {
    fn default() -> Self {
        Self::new(3)
    }
}

impl CrossFileRule for FeatureEnvyRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn default_severity(&self) -> Severity {
        Severity::Minor
    }

    fn issue_type(&self) -> IssueType {
        IssueType::CodeSmell
    }

    fn metadata(&self) -> RuleMetadata {
        RuleMetadata {
            description: "A method accesses another class's members far more than its own — it likely belongs on that other class instead.".into(),
            tags: vec!["design".into(), "feature-envy".into(), "cross-file".into()],
            cwe: None,
            produces_hotspots: false,
        }
    }

    fn check(&self, files: &[(SourceFile, AstNode)]) -> Vec<(usize, Finding)> {
        let views: Vec<(&str, &AstNode)> =
            files.iter().map(|(file, ast)| (file.path(), ast)).collect();
        let registry = ClassRegistry::build_cross_file(&views);
        let mut findings = Vec::new();
        for class in registry.iter() {
            let Some(index) = files.iter().position(|(file, _)| file.path() == class.file) else {
                continue;
            };
            for method in &class.methods {
                // Foreign-typed parameters: a declared type that resolves to
                // a *different* known class, possibly declared in another
                // file. An unresolvable or primitive type is silently
                // skipped — no false positive on `fn f(count: number)`.
                let foreign_params: Vec<&str> = method
                    .params
                    .iter()
                    .filter_map(|p| {
                        let type_name = p.declared_type.as_deref()?;
                        if type_name == class.name {
                            return None;
                        }
                        registry.get(type_name)?;
                        Some(p.name.as_str())
                    })
                    .collect();
                if foreign_params.is_empty() {
                    continue;
                }
                let mut per_param: HashMap<&str, usize> = HashMap::new();
                let mut own_total = 0usize;
                for &param in &foreign_params {
                    let (own, foreign) = count_accesses(method.node, param);
                    own_total = own_total.max(own);
                    per_param.insert(param, foreign);
                }
                let Some((&envied_param, &foreign_count)) =
                    per_param.iter().max_by_key(|&(_, &count)| count)
                else {
                    continue;
                };
                if foreign_count >= self.min_foreign_accesses && foreign_count > own_total {
                    findings.push((
                        index,
                        Finding::new(
                            format!(
                                "`{}::{}` accesses `{envied_param}` {foreign_count} times but its own members only {own_total} times — this logic likely belongs on `{envied_param}`'s class instead",
                                class.name, method.name
                            ),
                            method.span,
                        ),
                    ));
                }
            }
        }
        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vord_ast::LanguageIdentifier;
    use vord_rules_engine::AstParser;

    fn check_ts(code: &str) -> Vec<Finding> {
        let file = SourceFile::new("t.ts", code, LanguageIdentifier::typescript()).unwrap();
        let ast = vord_parser_typescript::TypeScriptParser::new()
            .parse(&file)
            .unwrap();
        let files = vec![(file, ast)];
        FeatureEnvyRule::default()
            .check(&files)
            .into_iter()
            .map(|(_, f)| f)
            .collect()
    }

    #[test]
    fn flags_method_favoring_a_foreign_typed_parameter() {
        let findings = check_ts(
            "class Address {\n  street: string = \"\";\n  city: string = \"\";\n  zip: string = \"\";\n}\nclass Invoice {\n  total: number = 0;\n  format(addr: Address): string {\n    return addr.street + addr.city + addr.zip;\n  }\n}\n",
        );
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("Invoice::format"));
        assert!(findings[0].message.contains("addr"));
    }

    #[test]
    fn allows_method_favoring_its_own_members() {
        let findings = check_ts(
            "class Address {\n  street: string = \"\";\n  city: string = \"\";\n  zip: string = \"\";\n}\nclass Invoice {\n  total: number = 0;\n  tax: number = 0;\n  format(addr: Address): string {\n    return this.total + this.tax + addr.street;\n  }\n}\n",
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn ignores_unresolvable_parameter_types() {
        let findings = check_ts(
            "class Invoice {\n  format(cfg: Config): string {\n    return cfg.a + cfg.b + cfg.c;\n  }\n}\n",
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn ignores_accesses_below_the_threshold() {
        let findings = check_ts(
            "class Address {\n  street: string = \"\";\n}\nclass Invoice {\n  format(addr: Address): string {\n    return addr.street;\n  }\n}\n",
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn python_self_attribute_counts_as_own_access() {
        let file = SourceFile::new(
            "t.py",
            "class Address:\n    def __init__(self):\n        self.street = \"\"\n        self.city = \"\"\n\nclass Invoice:\n    def __init__(self):\n        self.total = 0\n\n    def format(self, addr: Address):\n        return addr.street + addr.city\n",
            LanguageIdentifier::python(),
        )
        .unwrap();
        let ast = vord_parser_python::PythonParser::new()
            .parse(&file)
            .unwrap();
        let files = vec![(file, ast)];
        let findings: Vec<Finding> = FeatureEnvyRule::new(2)
            .check(&files)
            .into_iter()
            .map(|(_, f)| f)
            .collect();
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("Invoice::format"));
    }

    #[test]
    fn flags_method_favoring_a_parameter_typed_as_a_class_declared_in_another_file() {
        let address_file = SourceFile::new(
            "address.ts",
            "class Address {\n  street: string = \"\";\n  city: string = \"\";\n  zip: string = \"\";\n}\n",
            LanguageIdentifier::typescript(),
        )
        .unwrap();
        let invoice_file = SourceFile::new(
            "invoice.ts",
            "class Invoice {\n  total: number = 0;\n  format(addr: Address): string {\n    return addr.street + addr.city + addr.zip;\n  }\n}\n",
            LanguageIdentifier::typescript(),
        )
        .unwrap();
        let parser = vord_parser_typescript::TypeScriptParser::new();
        let files = vec![
            (address_file.clone(), parser.parse(&address_file).unwrap()),
            (invoice_file.clone(), parser.parse(&invoice_file).unwrap()),
        ];
        let findings = FeatureEnvyRule::default().check(&files);
        assert_eq!(findings.len(), 1);
        let (index, finding) = &findings[0];
        assert_eq!(files[*index].0.path(), "invoice.ts");
        assert!(finding.message.contains("Invoice::format"));
        assert!(finding.message.contains("addr"));
    }
}
