//! Rule: flags SQL statements built from untrusted user input — the
//! classic Java SQL injection pattern in the OWASP Benchmark (and real
//! JDBC/JdbcTemplate code).
//!
//! Strategy: intra-file value flow ([`ServletTaint`]) over SQL execution
//! sinks: `Statement.execute*`, `Connection.prepareStatement`,
//! `JdbcTemplate.query*`. Parameterized use (`prepareStatement` with a
//! constant query plus `setString(1, …)` binding) stays silent — only the
//! *query string* is judged.

use vord_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use vord_rules_engine::{Finding, IssueType, Rule, RuleId, Severity};

use crate::java_servlet_taint::{split_call, ServletTaint};

/// Methods that execute a SQL string taken from an argument.
const SQL_SINKS: &[&str] = &[
    "execute",
    "executeQuery",
    "executeUpdate",
    "executeBatch",
    "addBatch",
    "prepareStatement",
    "prepareCall",
    "query",
    "queryForMap",
    "queryForList",
    "queryForObject",
    "queryForRowSet",
    "queryForInt",
    "queryForLong",
    "queryForSql",
    "batchUpdate",
    "update",
];

/// Receivers that make a short, otherwise-ambiguous sink name a SQL call.
/// `update` on its own is far too common to treat as SQL — `MessageDigest`,
/// `PrintStream` and friends all have one — so it only counts when it is
/// invoked on a Spring `JdbcTemplate`. `execute` needs no such gate: on a
/// JDBC `Statement` it is unambiguously SQL, and it is not in the corpus
/// outside that role.
const SQL_RECEIVERS: &[&str] = &["JDBCtemplate", "JdbcTemplate", "jdbcTemplate", "template"];

/// Sink names that need their receiver checked before they are believed.
const AMBIGUOUS_SINKS: &[&str] = &["update", "query"];

pub struct SqlInjectionJavaRule {
    id: RuleId,
}

impl SqlInjectionJavaRule {
    pub fn new() -> Self {
        Self {
            id: RuleId::new("owasp:sql-injection-java").expect("valid rule id"),
        }
    }
}

impl Default for SqlInjectionJavaRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for SqlInjectionJavaRule {
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
            description: "Untrusted user input is concatenated into a SQL statement, which allows SQL injection. Use a PreparedStatement with parameter binding instead.".into(),
            tags: vec!["security".into(), "owasp-a03".into(), "sql-injection".into(), "java".into()],
            cwe: Some(89),
            produces_hotspots: false,
        }
    }

    fn check(&self, _file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        let state = ServletTaint::analyze(ast);
        ast.descendants()
            .filter(|n| *n.kind() == NodeKind::Call)
            .filter_map(|node| {
                let call = split_call(node)?;
                if !SQL_SINKS.contains(&call.method.as_str()) {
                    return None;
                }
                if AMBIGUOUS_SINKS.contains(&call.method.as_str())
                    && !SQL_RECEIVERS.iter().any(|r| call.receiver_text.contains(r))
                {
                    return None;
                }
                let tainted_arg = call.args.iter().any(|arg| state.is_tainted(arg));
                tainted_arg.then(|| {
                    Finding::new(
                        "user input from a servlet request reaches a SQL statement without parameterized queries — this is a SQL injection vulnerability",
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
        SqlInjectionJavaRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_concatenated_query_for_map() {
        let findings = check(
            "class T { void f(HttpServletRequest request) {\n String param = request.getParameter(\"x\");\n String sql = \"SELECT * from USERS where NAME='\" + param + \"'\";\n java.util.Map results = org.owasp.benchmark.helpers.DatabaseHelper.JDBCtemplate.queryForMap(sql);\n} }",
        );
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn flags_execute_query_with_tainted_sql() {
        let findings = check(
            "class T { void f(HttpServletRequest request) throws Exception {\n String bar = request.getParameter(\"x\");\n java.sql.Statement st = conn.createStatement();\n String sql = \"SELECT * from USERS where NAME='\" + bar + \"'\";\n java.sql.ResultSet rs = st.executeQuery(sql);\n} }",
        );
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn allows_parameterized_prepare_statement() {
        let findings = check(
            "class T { void f(HttpServletRequest request) throws Exception {\n String bar = request.getParameter(\"x\");\n java.sql.PreparedStatement ps = conn.prepareStatement(\"SELECT * from USERS where NAME = ?\");\n ps.setString(1, bar);\n ps.execute();\n} }",
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn allows_constant_query() {
        let findings = check(
            "class T { void f() throws Exception {\n java.sql.Statement st = conn.createStatement();\n st.executeQuery(\"SELECT 1\");\n} }",
        );
        assert!(findings.is_empty());
    }
}
