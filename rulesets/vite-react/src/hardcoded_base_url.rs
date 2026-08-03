//! Rule: a string or template literal starting `http://`/`https://` bound
//! to a `baseURL`/`endpoint`/`url`-shaped name (a variable, an assignment,
//! or an object-literal property), outside `src/infra/**` and outside
//! config files (`vite.config.ts`, `src/config/**`, …). A base URL scattered
//! across feature code is a URL Vord's `--sarif`-imported linters can't see
//! as *duplicated infrastructure*, and it means switching environments
//! means grepping the whole tree instead of editing one file.

use globset::GlobSet;
use vord_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use vord_rules_engine::{Finding, IssueType, Rule, RuleId, RuleMetadata, Severity};

use crate::common::{
    build_globset, is_config_path, is_excepted, is_infra_path, is_other, strip_quotes,
};

pub struct HardcodedBaseUrlRule {
    id: RuleId,
    exceptions: GlobSet,
}

impl HardcodedBaseUrlRule {
    pub fn new() -> Self {
        Self::with_exceptions(Vec::new())
    }

    pub fn with_exceptions(globs: Vec<String>) -> Self {
        Self {
            id: RuleId::new("vite-react:hardcoded-base-url").expect("valid rule id"),
            exceptions: build_globset(&globs),
        }
    }
}

impl Default for HardcodedBaseUrlRule {
    fn default() -> Self {
        Self::new()
    }
}

fn is_url_shaped_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower == "url" || lower == "endpoint" || lower.ends_with("baseurl") || lower.ends_with("url")
}

fn binding_name(node: &AstNode) -> Option<String> {
    if matches!(node.kind(), NodeKind::VariableDecl | NodeKind::Assignment) {
        let target = node.first_child()?;
        return (*target.kind() == NodeKind::Identifier).then(|| target.text().to_string());
    }
    if is_other(node, "pair") {
        let key = node.first_child()?;
        return match key.kind() {
            NodeKind::Identifier => Some(key.text().to_string()),
            NodeKind::StringLiteral => Some(strip_quotes(key.text())),
            _ => None,
        };
    }
    None
}

fn bound_values(node: &AstNode) -> &[AstNode] {
    if matches!(node.kind(), NodeKind::VariableDecl | NodeKind::Assignment) {
        return node.children().get(1..).unwrap_or(&[]);
    }
    node.children().get(1..2).unwrap_or(&[])
}

fn looks_like_url(literal: &AstNode) -> bool {
    if *literal.kind() != NodeKind::StringLiteral {
        return false;
    }
    let text = strip_quotes(literal.text());
    text.starts_with("http://") || text.starts_with("https://")
}

impl Rule for HardcodedBaseUrlRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn applies_to(&self, language: &LanguageIdentifier) -> bool {
        language.is_typescript() || language.is_javascript()
    }

    fn default_severity(&self) -> Severity {
        Severity::Major
    }

    fn issue_type(&self) -> IssueType {
        IssueType::CodeSmell
    }

    fn metadata(&self) -> RuleMetadata {
        RuleMetadata {
            description: "A `baseURL`/`endpoint`/`url`-named binding holds a hardcoded `http(s)://` literal outside `src/infra` and outside config files — switching environments means grepping the tree instead of editing the one place infra config lives.".into(),
            tags: vec![
                "vite-react".into(),
                "bulletproof-react".into(),
                "configuration".into(),
            ],
            cwe: None,
            produces_hotspots: false,
        }
    }

    fn check(&self, file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        if vord_rules_engine::is_test_only_path(file.path())
            || is_infra_path(file.path())
            || is_config_path(file.path())
            || is_excepted(file.path(), &self.exceptions)
        {
            return Vec::new();
        }
        let mut findings = Vec::new();
        for node in ast.descendants().filter(|n| {
            matches!(n.kind(), NodeKind::VariableDecl | NodeKind::Assignment) || is_other(n, "pair")
        }) {
            let Some(name) = binding_name(node) else {
                continue;
            };
            if !is_url_shaped_name(&name) {
                continue;
            }
            for value in bound_values(node) {
                if looks_like_url(value) {
                    findings.push(Finding::new(
                        format!(
                            "`{name}` is bound to a hardcoded URL outside `src/infra` — move it into the shared infra client's configuration (or `import.meta.env`) instead of hardcoding it here"
                        ),
                        value.span(),
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
    use vord_rules_engine::AstParser;

    fn ts(path: &str, code: &str) -> Vec<Finding> {
        let file = SourceFile::new(path, code, LanguageIdentifier::typescript()).unwrap();
        let ast = vord_parser_typescript::TypeScriptParser::new()
            .parse(&file)
            .unwrap();
        HardcodedBaseUrlRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_a_hardcoded_base_url_variable() {
        let findings = ts(
            "src/features/user/api/client.ts",
            "const baseURL = 'https://api.example.com';\n",
        );
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("`baseURL`"));
    }

    #[test]
    fn flags_a_hardcoded_endpoint_object_property() {
        let findings = ts(
            "src/features/user/api/client.ts",
            "const config = {\n  endpoint: 'https://api.example.com/users',\n};\n",
        );
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("`endpoint`"));
    }

    #[test]
    fn flags_an_api_url_assignment() {
        let findings = ts(
            "src/components/Widget.tsx",
            "let apiUrl;\napiUrl = 'http://localhost:4000';\n",
        );
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn silent_inside_infra() {
        assert!(
            ts(
                "src/infra/http/client.ts",
                "const baseURL = 'https://api.example.com';\n",
            )
            .is_empty()
        );
    }

    #[test]
    fn silent_in_a_config_file() {
        assert!(
            ts(
                "vite.config.ts",
                "const baseURL = 'https://api.example.com';\n",
            )
            .is_empty()
        );
    }

    #[test]
    fn silent_on_an_unrelated_variable() {
        assert!(
            ts(
                "src/features/user/api/client.ts",
                "const username = 'https://not-actually-a-url-name';\n",
            )
            .is_empty()
        );
    }

    #[test]
    fn silent_on_a_non_url_string() {
        assert!(
            ts(
                "src/features/user/api/client.ts",
                "const baseURL = '/api/v1';\n",
            )
            .is_empty()
        );
    }
}
