//! Security hotspot: flags `"0.0.0.0"` passed as a bind host (`app.run`,
//! `socket.bind`, ...). Binding to all interfaces exposes the service on
//! every network the host is attached to, not just the intended one — a
//! reviewer must confirm that's actually the deployment's intent (e.g. a
//! container where 0.0.0.0 is required) rather than an accidental
//! widening from `127.0.0.1`.

use yunq_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use yunq_rules_engine::{Finding, IssueType, Rule, RuleId, Severity};

const BIND_ALL: &str = "0.0.0.0";

fn other_kind_name(node: &AstNode) -> Option<&str> {
    match node.kind() {
        NodeKind::Other(name) => Some(name.as_ref()),
        _ => None,
    }
}

fn string_content(node: &AstNode) -> Option<&str> {
    if *node.kind() != NodeKind::StringLiteral {
        return None;
    }
    node.children().iter().find(|c| other_kind_name(c) == Some("string_content")).map(|c| c.text())
}

fn binds_all_interfaces(call: &AstNode) -> bool {
    let Some(args) = call.children().iter().find(|c| other_kind_name(c) == Some("argument_list")) else { return false };
    args.descendants().any(|n| string_content(n) == Some(BIND_ALL))
}

pub struct BindAllInterfacesRule {
    id: RuleId,
}

impl BindAllInterfacesRule {
    pub fn new() -> Self {
        Self { id: RuleId::new("python:bind-all-interfaces").expect("valid rule id") }
    }
}

impl Default for BindAllInterfacesRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for BindAllInterfacesRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn applies_to(&self, lang: &LanguageIdentifier) -> bool {
        *lang == LanguageIdentifier::python()
    }

    fn default_severity(&self) -> Severity {
        Severity::Minor
    }

    fn issue_type(&self) -> IssueType {
        IssueType::Vulnerability
    }

    fn remediation_effort_minutes(&self) -> u32 {
        10
    }

    fn metadata(&self) -> yunq_rules_engine::RuleMetadata {
        yunq_rules_engine::RuleMetadata {
            description: "Binding to 0.0.0.0 exposes the service on every network interface, not just the intended one; confirm that's actually this deployment's intent.".into(),
            tags: vec!["security".into(), "cwe".into()],
            cwe: Some(605),
            produces_hotspots: true,
        }
    }

    fn check(&self, file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        if yunq_rules_engine::is_test_only_path(file.path()) {
            return Vec::new();
        }
        ast.descendants()
            .filter(|n| *n.kind() == NodeKind::Call)
            .filter(|call| call.first_child().is_some_and(|callee| callee.text().ends_with(".run") || callee.text().ends_with(".bind") || callee.text().ends_with(".listen")))
            .filter(|call| binds_all_interfaces(call))
            .map(|call| Finding::hotspot("make sure binding to 0.0.0.0 (every network interface) is intentional here", call.span()))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use yunq_rules_engine::{AstParser, FindingKind};

    use super::*;

    fn findings(code: &str) -> Vec<Finding> {
        let file = SourceFile::new("t.py", code, LanguageIdentifier::python()).unwrap();
        let ast = yunq_parser_python::PythonParser::new().parse(&file).unwrap();
        BindAllInterfacesRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_flask_run_bind_all() {
        let f = findings("app.run(host='0.0.0.0')\n");
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].kind, FindingKind::Hotspot);
    }

    #[test]
    fn flags_socket_bind_all() {
        assert_eq!(findings("s.bind(('0.0.0.0', 8080))\n").len(), 1);
    }

    #[test]
    fn allows_localhost_bind() {
        assert!(findings("app.run(host='127.0.0.1')\n").is_empty());
    }
}
