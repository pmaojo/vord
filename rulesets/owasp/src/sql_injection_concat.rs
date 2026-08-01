//! Rule: flags SQL queries constructed via string concatenation or template literals.

use yunq_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use yunq_rules_engine::{Finding, IssueType, Rule, RuleId, RuleMetadata, Severity};

fn is_sql_concat_or_template(line: &str) -> bool {
    let upper = line.to_uppercase();

    let has_sql_keyword = upper.contains("SELECT ")
        || upper.contains("INSERT INTO ")
        || upper.contains("UPDATE ")
        || upper.contains("DELETE FROM ")
        || upper.contains("DROP TABLE ")
        || upper.contains("ALTER TABLE ")
        || upper.contains("CREATE TABLE ")
        || (upper.contains("WHERE ")
            && (upper.contains("SELECT") || upper.contains("DELETE") || upper.contains("UPDATE")));

    if !has_sql_keyword {
        return false;
    }

    // Check for JS/TS Template Literals: `SELECT ... ${var}`
    if line.contains('`') && line.contains("${") {
        return true;
    }

    // Check for Python f-strings: f"SELECT ... {var}" or f'SELECT ... {var}'
    if (line.contains("f\"") || line.contains("f'")) && line.contains('{') && line.contains('}') {
        return true;
    }

    // Check for Sprintf / format calls: fmt.Sprintf("SELECT ... %s", ...) or sprintf(...) or format!(...)
    if (line.contains("fmt.Sprintf") || line.contains("sprintf") || line.contains("format!"))
        && (line.contains("%s") || line.contains("%d") || line.contains("{}"))
    {
        return true;
    }

    // Check for String Concatenation (+) with quotes containing SQL keywords
    if line.contains('+') {
        let has_quoted_sql = line.contains("\"SELECT")
            || line.contains("'SELECT")
            || line.contains("\"select")
            || line.contains("'select")
            || line.contains("\"INSERT")
            || line.contains("'INSERT")
            || line.contains("\"insert")
            || line.contains("'insert")
            || line.contains("\"UPDATE")
            || line.contains("'UPDATE")
            || line.contains("\"update")
            || line.contains("'update")
            || line.contains("\"DELETE")
            || line.contains("'DELETE")
            || line.contains("\"delete")
            || line.contains("'delete")
            || line.contains("\"WHERE")
            || line.contains("'WHERE")
            || line.contains("\"where")
            || line.contains("'where")
            || line.contains("\" FROM")
            || line.contains("' FROM")
            || line.contains("\" from")
            || line.contains("' from");

        if has_quoted_sql {
            return true;
        }
    }

    // Check for PHP dot concatenation (.) with quotes containing SQL keywords
    if line.contains('.') {
        let has_php_concat = (line.contains("\"SELECT")
            || line.contains("'SELECT")
            || line.contains("\"WHERE")
            || line.contains("'WHERE")
            || line.contains("\"select")
            || line.contains("'select"))
            && (line.contains(" .") || line.contains(". "));
        if has_php_concat {
            return true;
        }
    }

    false
}

pub struct SqlInjectionConcatRule {
    id: RuleId,
}

impl SqlInjectionConcatRule {
    pub fn new() -> Self {
        Self {
            id: RuleId::new("owasp:sql-injection-concat").expect("valid rule id"),
        }
    }
}

impl Default for SqlInjectionConcatRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for SqlInjectionConcatRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn applies_to(&self, _language: &LanguageIdentifier) -> bool {
        true
    }

    fn default_severity(&self) -> Severity {
        Severity::Critical
    }

    fn issue_type(&self) -> IssueType {
        IssueType::Vulnerability
    }

    fn metadata(&self) -> RuleMetadata {
        RuleMetadata {
            description: "Constructing SQL queries via string concatenation or template literals can lead to SQL injection vulnerabilities. Use parameterized queries instead.".into(),
            tags: vec!["security".into(), "owasp-a03".into(), "injection".into(), "sql".into()],
            cwe: Some(89),
            produces_hotspots: false,
        }
    }

    fn check(&self, file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        if ast.kind() != &NodeKind::SourceUnit {
            return Vec::new();
        }
        if yunq_rules_engine::is_test_only_path(file.path()) {
            return Vec::new();
        }
        let test_ranges = yunq_rules_engine::rust_test_module_ranges(file.content());

        let mut findings = Vec::new();
        let content = file.content();

        for (idx, line) in content.lines().enumerate() {
            let line_no = (idx + 1) as u32;
            if yunq_rules_engine::in_ranges(&test_ranges, line_no) {
                continue;
            }
            let trimmed = line.trim();
            if trimmed.starts_with("//") || trimmed.starts_with('#') || trimmed.starts_with('*') {
                continue;
            }

            if is_sql_concat_or_template(line) {
                findings.push(Finding::new(
                    "SQL query constructed via string concatenation or template literal; use parameterized queries instead",
                    yunq_ast::Span::new(line_no, 1, line_no, line.len().max(1) as u32),
                ));
            }
        }

        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_plus_concatenation_sql() {
        let code = "const query = \"SELECT * FROM users WHERE id = \" + id;\n";
        let file = SourceFile::new("app.js", code, LanguageIdentifier::typescript()).unwrap();
        let ast = AstNode::new(
            NodeKind::SourceUnit,
            yunq_ast::Span::new(1, 1, 1, code.len() as u32),
            code,
            vec![],
        );
        let rule = SqlInjectionConcatRule::new();
        let findings = rule.check(&file, &ast);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn flags_template_literal_sql() {
        let code = "const query = `SELECT * FROM users WHERE id = ${id}`;\n";
        let file = SourceFile::new("app.js", code, LanguageIdentifier::typescript()).unwrap();
        let ast = AstNode::new(
            NodeKind::SourceUnit,
            yunq_ast::Span::new(1, 1, 1, code.len() as u32),
            code,
            vec![],
        );
        let rule = SqlInjectionConcatRule::new();
        let findings = rule.check(&file, &ast);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn flags_python_fstring_sql() {
        let code = "query = f\"SELECT * FROM users WHERE id = {user_id}\"\n";
        let file = SourceFile::new("app.py", code, LanguageIdentifier::python()).unwrap();
        let ast = AstNode::new(
            NodeKind::SourceUnit,
            yunq_ast::Span::new(1, 1, 1, code.len() as u32),
            code,
            vec![],
        );
        let rule = SqlInjectionConcatRule::new();
        let findings = rule.check(&file, &ast);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn allows_parameterized_sql_query() {
        let code = "const query = \"SELECT * FROM users WHERE id = ?\";\n";
        let file = SourceFile::new("app.js", code, LanguageIdentifier::typescript()).unwrap();
        let ast = AstNode::new(
            NodeKind::SourceUnit,
            yunq_ast::Span::new(1, 1, 1, code.len() as u32),
            code,
            vec![],
        );
        let rule = SqlInjectionConcatRule::new();
        let findings = rule.check(&file, &ast);
        assert!(findings.is_empty());
    }

    #[test]
    fn ignores_comments() {
        let code = "// SELECT * FROM users WHERE id = \" + id\n";
        let file = SourceFile::new("app.js", code, LanguageIdentifier::typescript()).unwrap();
        let ast = AstNode::new(
            NodeKind::SourceUnit,
            yunq_ast::Span::new(1, 1, 1, code.len() as u32),
            code,
            vec![],
        );
        let rule = SqlInjectionConcatRule::new();
        let findings = rule.check(&file, &ast);
        assert!(findings.is_empty());
    }
}
