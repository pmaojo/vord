//! Rule: flags TypeScript's legacy `namespace Foo { ... }` construct used
//! in a file that also has ES `import`/`export` statements. `namespace` is
//! a pre-ES-module organizational feature; a file that's already an ES
//! module (has real `import`/`export`) gets nothing from mixing in the old
//! namespace pattern besides confusion about which mechanism actually
//! scopes what.

use vord_ast::{AstNode, LanguageIdentifier, SourceFile};
use vord_rules_engine::{Finding, IssueType, Rule, RuleId, RuleMetadata, Severity};

use crate::common::is_other;

fn is_module_statement(node: &AstNode) -> bool {
    is_other(node, "import_statement") || is_other(node, "export_statement")
}

pub struct NamespaceUsageInModuleCodeRule {
    id: RuleId,
}

impl NamespaceUsageInModuleCodeRule {
    pub fn new() -> Self {
        Self {
            id: RuleId::new("typescript:namespace-usage-in-module-code").expect("valid rule id"),
        }
    }
}

impl Default for NamespaceUsageInModuleCodeRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for NamespaceUsageInModuleCodeRule {
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
            description: "This file already uses ES `import`/`export`, so it's an ES module — the legacy `namespace` construct adds a second, older scoping mechanism on top for no benefit. Convert the namespace's members to module-level exports.".into(),
            tags: vec!["typescript".into(), "maintainability".into()],
            cwe: None,
            produces_hotspots: false,
        }
    }

    fn check(&self, _file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        // Only top-level import/export statements count as "this file is
        // already an ES module" — a `namespace` re-exporting its own
        // members (`export const a = 1;` inside the namespace body) is the
        // normal way to use one and must not itself trigger the rule.
        if !ast.children().iter().any(is_module_statement) {
            return Vec::new();
        }
        ast.descendants()
            .filter(|n| is_other(n, "internal_module"))
            .map(|n| {
                Finding::new(
                    "this legacy `namespace` is declared in a file that already uses ES `import`/`export`; convert its members to module-level exports instead",
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
        NamespaceUsageInModuleCodeRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_namespace_alongside_import() {
        let code = "import { x } from 'y';\nnamespace Foo {\n  export const a = 1;\n}\n";
        assert_eq!(check(code).len(), 1);
    }

    #[test]
    fn flags_namespace_alongside_export() {
        let code = "export const x = 1;\nnamespace Foo {\n  export const a = 1;\n}\n";
        assert_eq!(check(code).len(), 1);
    }

    #[test]
    fn allows_namespace_in_a_non_module_file() {
        let code = "namespace Foo {\n  export const a = 1;\n}\n";
        assert!(check(code).is_empty());
    }

    #[test]
    fn allows_module_file_with_no_namespace() {
        let code = "import { x } from 'y';\nexport const a = x + 1;\n";
        assert!(check(code).is_empty());
    }
}
