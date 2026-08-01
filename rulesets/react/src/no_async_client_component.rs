//! Rule: flags declaring a Client React component function as `async function Component(...)`.

use yunq_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use yunq_rules_engine::{declare_rule_id, Finding, IssueType, Rule, RuleId, RuleMetadata, Severity};

use crate::common::{callee_name, is_hook_name, is_jsx_kind, is_other};

declare_rule_id!(NoAsyncClientComponentRule, "react:no-async-client-component");

impl Rule for NoAsyncClientComponentRule {
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
            description: "Client React components cannot be `async` functions. Async component functions are only supported in Server Components.".into(),
            tags: vec!["react".into(), "nextjs".into(), "client-component".into()],
            cwe: None,
            produces_hotspots: false,
        }
    }

    fn check(&self, file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        let mut findings = Vec::new();
        let is_file_use_client = file.content().contains("'use client'") || file.content().contains("\"use client\"");

        for node in ast.descendants() {
            if !is_function_node(node) {
                continue;
            }

            if !is_async_function(node) {
                continue;
            }

            if !is_component_function(node) {
                continue;
            }

            let is_client = is_file_use_client || contains_hook_call(node);
            if is_client {
                findings.push(Finding::new(
                    "Client React component cannot be an `async` function. Remove `async` or convert to a Server Component.",
                    node.span(),
                ));
            }
        }

        findings
    }
}

fn is_function_node(node: &AstNode) -> bool {
    *node.kind() == NodeKind::FunctionDef
        || is_other(node, "arrow_function")
        || is_other(node, "function_declaration")
        || is_other(node, "function_expression")
}

fn is_async_function(node: &AstNode) -> bool {
    let text = node.text().trim();
    text.starts_with("async") || node.children().iter().any(|c| c.text() == "async")
}

fn is_component_function(node: &AstNode) -> bool {
    // Check if function name is PascalCase
    for child in node.children() {
        if *child.kind() == NodeKind::Identifier {
            let text = child.text();
            if text.starts_with(|c: char| c.is_ascii_uppercase()) {
                return true;
            }
        }
    }

    // Check if function returns or contains JSX
    node.descendants().any(is_jsx_kind)
}

fn contains_hook_call(node: &AstNode) -> bool {
    node.descendants().any(|n| {
        *n.kind() == NodeKind::Call && callee_name(n).is_some_and(is_hook_name)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use yunq_rules_engine::AstParser;

    fn check(code: &str) -> Vec<Finding> {
        let file = SourceFile::new("t.tsx", code, LanguageIdentifier::typescript()).unwrap();
        let ast = yunq_parser_typescript::TypeScriptParser::new()
            .parse(&file)
            .unwrap();
        NoAsyncClientComponentRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_async_component_in_use_client_file() {
        let code = "'use client';\nexport async function UserProfile() { return <div>User</div>; }\n";
        let findings = check(code);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("Client React component cannot be an `async` function"));
    }

    #[test]
    fn flags_async_arrow_component_in_use_client_file() {
        let code = "'use client';\nconst Component = async () => <div>Client</div>;\n";
        let findings = check(code);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn flags_async_component_using_hooks() {
        let code = "async function MyComponent() { const [s, setS] = useState(0); return <div>{s}</div>; }\n";
        let findings = check(code);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn allows_async_server_component() {
        let code = "export async function ServerComponent() { const res = await fetch('/api'); return <div>Server</div>; }\n";
        let findings = check(code);
        assert!(findings.is_empty());
    }

    #[test]
    fn allows_sync_client_component() {
        let code = "'use client';\nexport function ClientComponent() { return <div>Client</div>; }\n";
        let findings = check(code);
        assert!(findings.is_empty());
    }

    #[test]
    fn allows_async_helper_function() {
        let code = "'use client';\nasync function fetchUserData(id: string) { return fetch('/api/user/' + id); }\n";
        let findings = check(code);
        assert!(findings.is_empty());
    }
}
