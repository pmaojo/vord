//! Rule: flags LDAP filters built from untrusted user input — the OWASP
//! Benchmark "ldapi" family (CWE-90).
//!
//! Strategy: intra-file value flow ([`ServletTaint`]) — `DirContext.search`
//! (or any `search` on a directory context) is a finding when its filter or
//! name argument is user-controlled. Constant filters stay silent.

use vord_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use vord_rules_engine::{Finding, IssueType, Rule, RuleId, Severity};

use crate::java_servlet_taint::{split_call, ServletTaint};

pub struct LdapInjectionJavaRule {
    id: RuleId,
}

impl LdapInjectionJavaRule {
    pub fn new() -> Self {
        Self {
            id: RuleId::new("owasp:ldap-injection-java").expect("valid rule id"),
        }
    }
}

impl Default for LdapInjectionJavaRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for LdapInjectionJavaRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn applies_to(&self, language: &LanguageIdentifier) -> bool {
        *language == LanguageIdentifier::java()
    }

    fn default_severity(&self) -> Severity {
        Severity::Blocker
    }

    fn issue_type(&self) -> IssueType {
        IssueType::Vulnerability
    }

    fn remediation_effort_minutes(&self) -> u32 {
        15
    }

    fn metadata(&self) -> vord_rules_engine::RuleMetadata {
        vord_rules_engine::RuleMetadata {
            description: "Untrusted user input is concatenated into an LDAP search filter, which allows LDAP injection. Escape or validate filter values before building the query.".into(),
            tags: vec!["security".into(), "owasp-a03".into(), "ldap".into(), "java".into()],
            cwe: Some(90),
            produces_hotspots: false,
        }
    }

    fn check(&self, _file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        let state = ServletTaint::analyze(ast);
        ast.descendants()
            .filter(|n| *n.kind() == NodeKind::Call)
            .filter_map(|node| {
                let call = split_call(node)?;
                if call.method != "search" {
                    return None;
                }
                let receiver = call.receiver?;
                if !state.is_dir_context(receiver) {
                    return None;
                }
                let tainted_arg = call.args.iter().any(|arg| state.is_tainted(arg));
                tainted_arg.then(|| {
                    Finding::new(
                        "user input from a servlet request reaches an LDAP search filter without escaping — this is an LDAP injection vulnerability",
                        node.span(),
                    )
                })
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
        let file = SourceFile::new("Test.java", code, LanguageIdentifier::java()).unwrap();
        let ast = vord_parser_java::JavaParser::new().parse(&file).unwrap();
        LdapInjectionJavaRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_tainted_filter() {
        let findings = check(
            "class T { void f(HttpServletRequest request) throws Exception {\n String param = request.getParameter(\"x\");\n String filter = \"(&(objectclass=person))(|(uid=\" + param + \")(street={0}))\";\n javax.naming.directory.DirContext ctx = ads.getDirContext();\n ctx.search(\"ou=system\", filter, sc);\n} }",
        );
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn allows_constant_filter() {
        let findings = check(
            "class T { void f() throws Exception {\n javax.naming.directory.DirContext ctx = ads.getDirContext();\n ctx.search(\"ou=system\", \"(objectclass=person)\", sc);\n} }",
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn ignores_search_on_other_receivers() {
        let findings = check(
            "class T { void f(HttpServletRequest request) throws Exception {\n String bar = request.getParameter(\"x\");\n index.search(bar);\n} }",
        );
        assert!(findings.is_empty());
    }
}
