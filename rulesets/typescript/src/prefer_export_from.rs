//! Rule: a name is imported only to be immediately re-exported
//! (`import { Form } from './form'; export { Form };`) — collapse the two
//! statements into a single `export { Form } from './form';`. The
//! intermediate import buys nothing: the name is never used locally, so
//! importing it just to hand it back out is an unnecessary indirection
//! (and, in bundlers that don't tree-shake perfectly, an extra binding to
//! resolve). Mirrors SonarQube's `S6759`/`prefer_reexport_from`-style
//! check.

use vord_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use vord_rules_engine::{Finding, IssueType, Rule, RuleId, RuleMetadata, Severity};

use crate::common::is_other;

/// The bound local name of a `named_imports`' `import_specifier`: the
/// aliased name for `orig as local`, otherwise the sole identifier.
fn import_specifier_local_name(specifier: &AstNode) -> Option<&str> {
    let idents: Vec<&AstNode> = specifier
        .children()
        .iter()
        .filter(|c| *c.kind() == NodeKind::Identifier)
        .collect();
    idents.last().map(|n| n.text())
}

/// The local name an `export_clause`'s `export_specifier` references: the
/// first identifier (`local` in both `export { local }` and
/// `export { local as exported }`).
fn export_specifier_local_name(specifier: &AstNode) -> Option<&str> {
    specifier
        .children()
        .iter()
        .find(|c| *c.kind() == NodeKind::Identifier)
        .map(|n| n.text())
}

/// `(module_specifier, local_name)` for every named import binding in a
/// bare (non-`export ... from`) `import_statement`.
fn named_imports_from(node: &AstNode) -> Vec<(&str, &str)> {
    if !is_other(node, "import_statement") {
        return Vec::new();
    }
    let Some(module) = node
        .children()
        .iter()
        .find(|c| *c.kind() == NodeKind::StringLiteral)
    else {
        return Vec::new();
    };
    let module_text = module
        .text()
        .trim_matches(|c| c == '\'' || c == '"' || c == '`');
    node.descendants()
        .filter(|n| is_other(n, "import_specifier"))
        .filter_map(|specifier| {
            import_specifier_local_name(specifier).map(|name| (module_text, name))
        })
        .collect()
}

/// Every `export_specifier` local name in a bare `export { ... };`
/// statement (one with no trailing `from '<module>'` source).
fn bare_export_specifiers(node: &AstNode) -> Vec<&AstNode> {
    if !is_other(node, "export_statement") {
        return Vec::new();
    }
    let has_source = node
        .children()
        .iter()
        .any(|c| *c.kind() == NodeKind::StringLiteral);
    if has_source {
        return Vec::new();
    }
    node.descendants()
        .filter(|n| is_other(n, "export_specifier"))
        .collect()
}

pub struct PreferExportFromRule {
    id: RuleId,
}

impl PreferExportFromRule {
    pub fn new() -> Self {
        Self {
            id: RuleId::new("typescript:prefer-export-from").expect("valid rule id"),
        }
    }
}

impl Default for PreferExportFromRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for PreferExportFromRule {
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
            description: "A name is imported only to be re-exported unchanged; collapse `import { X } from 'm'; export { X };` into `export { X } from 'm';` instead of binding a local name that is never used.".into(),
            tags: vec!["typescript".into(), "clarity".into(), "consistency".into()],
            cwe: None,
            produces_hotspots: false,
        }
    }

    fn check(&self, file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        if vord_rules_engine::is_test_only_path(file.path()) {
            return Vec::new();
        }

        let imports: Vec<(&str, &str)> = ast.descendants().flat_map(named_imports_from).collect();

        if imports.is_empty() {
            return Vec::new();
        }

        let mut findings = Vec::new();

        for export_stmt in ast
            .descendants()
            .filter(|n| is_other(n, "export_statement"))
        {
            for specifier in bare_export_specifiers(export_stmt) {
                let Some(local_name) = export_specifier_local_name(specifier) else {
                    continue;
                };
                let Some((module, _)) = imports.iter().find(|(_, name)| *name == local_name) else {
                    continue;
                };

                let occurrences = ast
                    .descendants()
                    .filter(|n| *n.kind() == NodeKind::Identifier && n.text() == local_name)
                    .count();
                // Exactly the import binding site and this export site: no
                // other use of the name anywhere in the file.
                if occurrences != 2 {
                    continue;
                }

                findings.push(Finding::new(
                    format!(
                        "`{local_name}` is imported only to be re-exported; use `export {{ {local_name} }} from '{module}'` instead"
                    ),
                    specifier.span(),
                ));
            }
        }

        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vord_rules_engine::AstParser;

    fn check(code: &str) -> Vec<Finding> {
        let file = SourceFile::new("t.tsx", code, LanguageIdentifier::typescript()).unwrap();
        let ast = vord_parser_typescript::TypeScriptParser::new()
            .parse(&file)
            .unwrap();
        PreferExportFromRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_import_then_bare_reexport() {
        let findings = check("import { Form } from './form';\nexport { Form };\n");
        assert_eq!(findings.len(), 1);
        assert!(
            findings[0]
                .message
                .contains("export { Form } from './form'")
        );
    }

    #[test]
    fn flags_aliased_reexport() {
        let findings =
            check("import { useFormField } from './form';\nexport { useFormField as useField };\n");
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn allows_reexport_when_name_is_also_used_locally() {
        let findings = check(
            "import { Form } from './form';\nfunction Wrapped() { return Form; }\nexport { Form };\n",
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn allows_export_that_already_uses_from() {
        let findings = check("export { Form } from './form';\n");
        assert!(findings.is_empty());
    }

    #[test]
    fn allows_export_of_a_locally_defined_name() {
        let findings = check("function Form() {}\nexport { Form };\n");
        assert!(findings.is_empty());
    }

    #[test]
    fn allows_default_export() {
        let findings = check("import Form from './form';\nexport default Form;\n");
        assert!(findings.is_empty());
    }
}
