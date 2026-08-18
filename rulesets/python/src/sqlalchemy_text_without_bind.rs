//! Rule: flags SQLAlchemy's `text(...)` construct given an eagerly-built
//! string (an f-string, or `%`/`+` applied before the call) instead of a
//! literal query with `:name` placeholders bound through `.bindparams()`
//! or an `execute()` parameters dict. `text()` does not parameterize the
//! value for you — interpolating it into the string is SQL injection just
//! like it is for a raw DB-API cursor.

use vord_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use vord_rules_engine::{Finding, IssueType, Rule, RuleId, Severity};

use crate::common::other_kind_name;

fn is_eager_built_string(arg: &AstNode) -> bool {
    match arg.kind() {
        NodeKind::StringLiteral => arg.first_child().is_some_and(|start| {
            other_kind_name(start) == Some("string_start")
                && start.text().trim_start().starts_with(['f', 'F'])
        }),
        // A `+`/`%` expression is only the injection-risk shape this rule
        // targets when it actually interpolates something other than
        // string literals — pure literal-to-literal concatenation, used
        // purely to split a long query across lines
        // (`"SELECT ..." + "WHERE ..."`), builds the exact same static
        // string every time and carries no more risk than a single
        // literal. Only the operator's own immediate operands are
        // checked (not a full recursive descent), since descending into a
        // `StringLiteral` operand would otherwise walk into its own
        // `string_content`/`string_start` children and misread those as
        // "non-literal".
        NodeKind::Other(name) => {
            name.as_ref() == "binary_operator"
                && arg.children().iter().any(|c| c.kind() != &NodeKind::StringLiteral)
        }
        _ => false,
    }
}

fn is_sqlalchemy_text_callee(callee: &AstNode) -> bool {
    let text = callee.text();
    text == "text" || text == "sqlalchemy.text" || text.ends_with(".text")
}

pub struct SqlalchemyTextWithoutBindRule {
    id: RuleId,
}

impl SqlalchemyTextWithoutBindRule {
    pub fn new() -> Self {
        Self {
            id: RuleId::new("python:sqlalchemy-raw-sql-without-bind").expect("valid rule id"),
        }
    }
}

impl Default for SqlalchemyTextWithoutBindRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for SqlalchemyTextWithoutBindRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn applies_to(&self, lang: &LanguageIdentifier) -> bool {
        *lang == LanguageIdentifier::python()
    }

    fn default_severity(&self) -> Severity {
        Severity::Blocker
    }

    fn issue_type(&self) -> IssueType {
        IssueType::Vulnerability
    }

    fn remediation_effort_minutes(&self) -> u32 {
        20
    }

    fn metadata(&self) -> vord_rules_engine::RuleMetadata {
        vord_rules_engine::RuleMetadata {
            description: "SQLAlchemy's text() does not parameterize a value interpolated into its string argument; build the query with :name placeholders and pass values through bindparams()/execute() parameters instead.".into(),
            tags: vec!["security".into(), "injection".into(), "cwe".into(), "owasp-top10".into()],
            cwe: Some(89),
            produces_hotspots: false,
        }
    }

    fn check(&self, file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        if crate::common::is_test_file(file.path()) {
            return Vec::new();
        }
        ast.descendants()
            .filter(|n| *n.kind() == NodeKind::Call)
            .filter_map(|call| {
                let callee = call.first_child()?;
                if !is_sqlalchemy_text_callee(callee) {
                    return None;
                }
                let args = call.children().iter().find(|c| other_kind_name(c) == Some("argument_list"))?;
                let first_arg = args.children().first()?;
                is_eager_built_string(first_arg).then(|| Finding::new("SQL text() is built by interpolating a value directly into the string; use :name placeholders and bind the value separately", call.span()))
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use vord_rules_engine::AstParser;

    use super::*;

    fn findings(code: &str) -> Vec<Finding> {
        let file = SourceFile::new("t.py", code, LanguageIdentifier::python()).unwrap();
        let ast = vord_parser_python::PythonParser::new()
            .parse(&file)
            .unwrap();
        SqlalchemyTextWithoutBindRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_fstring_query() {
        assert_eq!(
            findings("stmt = text(f'SELECT * FROM t WHERE id={id}')\n").len(),
            1
        );
    }

    #[test]
    fn flags_percent_formatted_query() {
        assert_eq!(
            findings("stmt = sqlalchemy.text('SELECT * FROM t WHERE id=%s' % id)\n").len(),
            1
        );
    }

    #[test]
    fn allows_literal_query_with_placeholder() {
        assert!(findings("stmt = text('SELECT * FROM t WHERE id=:id').bindparams(id=id)\n").is_empty());
    }

    #[test]
    fn ignores_unrelated_calls() {
        assert!(findings("stmt = format_message(f'hello {name}')\n").is_empty());
    }

    /// Regression: `+` used purely to concatenate two string *literals*
    /// (a common way to split a long, fully-static query across lines)
    /// builds the exact same static string every time — no interpolated
    /// value is involved, so this is not the injection-risk shape the
    /// rule targets.
    #[test]
    fn allows_pure_literal_concatenation() {
        let code = "stmt = text('SELECT * FROM t ' + 'WHERE id = :id').bindparams(id=id)\n";
        assert!(findings(code).is_empty());
    }
}
