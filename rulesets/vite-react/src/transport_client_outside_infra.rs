//! Rule: an `axios.create(...)` factory call or a `new Axios(...)`
//! construction anywhere outside `src/infra/**` — a transport client is
//! infrastructure by definition, and building one in a feature or a
//! component means every consumer now carries its own base URL, headers and
//! interceptor setup instead of sharing the one this project already has.

use globset::GlobSet;
use vord_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use vord_rules_engine::{Finding, IssueType, Rule, RuleId, RuleMetadata, Severity};

use crate::common::{build_globset, is_excepted, is_infra_path};

pub struct TransportClientOutsideInfraRule {
    id: RuleId,
    exceptions: GlobSet,
}

impl TransportClientOutsideInfraRule {
    pub fn new() -> Self {
        Self::with_exceptions(Vec::new())
    }

    pub fn with_exceptions(globs: Vec<String>) -> Self {
        Self {
            id: RuleId::new("vite-react:transport-client-outside-infra").expect("valid rule id"),
            exceptions: build_globset(&globs),
        }
    }
}

impl Default for TransportClientOutsideInfraRule {
    fn default() -> Self {
        Self::new()
    }
}

fn is_axios_create(call: &AstNode) -> bool {
    let Some(callee) = call.first_child() else {
        return false;
    };
    if *callee.kind() != NodeKind::MemberAccess {
        return false;
    }
    let children = callee.children();
    let (Some(object), Some(property)) = (children.first(), children.last()) else {
        return false;
    };
    *object.kind() == NodeKind::Identifier
        && object.text() == "axios"
        && *property.kind() == NodeKind::Identifier
        && property.text() == "create"
}

/// tree-sitter-typescript maps `new_expression` onto the same neutral
/// `Call` kind as an ordinary call (`vord_ast`'s `NodeKind` has no separate
/// "construction" variant) — `text()` starting with `new ` is what tells the
/// two apart, since the `new` keyword itself is otherwise dropped from the
/// (named-children-only) neutral tree.
fn is_new_axios(call: &AstNode) -> bool {
    call.text().trim_start().starts_with("new ")
        && call
            .first_child()
            .is_some_and(|c| *c.kind() == NodeKind::Identifier && c.text() == "Axios")
}

fn walk(node: &AstNode, out: &mut Vec<Finding>) {
    if *node.kind() == NodeKind::Call {
        if is_axios_create(node) {
            out.push(Finding::new(
                "`axios.create(...)` is called outside `src/infra` — a transport client is infrastructure; build it once in `src/infra` and import that shared client everywhere else",
                node.span(),
            ));
        } else if is_new_axios(node) {
            out.push(Finding::new(
                "`new Axios(...)` is constructed outside `src/infra` — a transport client is infrastructure; build it once in `src/infra` and import that shared client everywhere else",
                node.span(),
            ));
        }
    }
    for child in node.children() {
        walk(child, out);
    }
}

impl Rule for TransportClientOutsideInfraRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn applies_to(&self, language: &LanguageIdentifier) -> bool {
        language.is_typescript() || language.is_javascript()
    }

    fn default_severity(&self) -> Severity {
        Severity::Blocker
    }

    fn issue_type(&self) -> IssueType {
        IssueType::CodeSmell
    }

    fn metadata(&self) -> RuleMetadata {
        RuleMetadata {
            description: "An HTTP transport client is constructed (`axios.create`/`new Axios`) outside `src/infra` — every consumer now carries its own base URL, headers and interceptor setup instead of sharing the project's single client.".into(),
            tags: vec![
                "vite-react".into(),
                "bulletproof-react".into(),
                "layering".into(),
            ],
            cwe: None,
            produces_hotspots: false,
        }
    }

    fn check(&self, file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        if vord_rules_engine::is_test_only_path(file.path())
            || is_infra_path(file.path())
            || is_excepted(file.path(), &self.exceptions)
        {
            return Vec::new();
        }
        let mut findings = Vec::new();
        walk(ast, &mut findings);
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
        TransportClientOutsideInfraRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_axios_create_in_a_feature() {
        let findings = ts(
            "src/features/user/api/client.ts",
            "const client = axios.create({ baseURL: 'https://api.example.com' });\n",
        );
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("axios.create"));
    }

    #[test]
    fn flags_new_axios_in_a_component() {
        let findings = ts(
            "src/components/Widget.tsx",
            "const client = new Axios({ baseURL: 'https://api.example.com' });\n",
        );
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("new Axios"));
    }

    #[test]
    fn silent_inside_infra() {
        assert!(
            ts(
                "src/infra/http/client.ts",
                "const client = axios.create({ baseURL: 'https://api.example.com' });\n",
            )
            .is_empty()
        );
    }

    #[test]
    fn silent_on_an_unrelated_axios_call() {
        assert!(
            ts(
                "src/features/user/api/client.ts",
                "axios.get('/api/user');\n"
            )
            .is_empty()
        );
    }

    #[test]
    fn silent_on_an_unrelated_new_expression() {
        assert!(
            ts(
                "src/features/user/api/client.ts",
                "const controller = new AbortController();\n"
            )
            .is_empty()
        );
    }
}
