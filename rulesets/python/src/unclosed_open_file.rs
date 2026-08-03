use vord_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use vord_rules_engine::{declare_rule_id, Finding, IssueType, Rule, RuleId, Severity};

declare_rule_id!(UnclosedOpenFileRule, "python:unclosed-open-file");

impl Rule for UnclosedOpenFileRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn applies_to(&self, language: &LanguageIdentifier) -> bool {
        *language == LanguageIdentifier::python()
    }

    fn default_severity(&self) -> Severity {
        Severity::Major
    }

    fn issue_type(&self) -> IssueType {
        IssueType::CodeSmell
    }

    fn check(&self, _file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        let mut findings = Vec::new();

        // `call` nodes are mapped to `NodeKind::Call` by the Python
        // tree-sitter adapter, never left as `NodeKind::Other("call")` —
        // matching on the latter meant this rule never fired on real code.
        // `open(...)` used as a `with` statement's context expression lives
        // under a `with_clause`/`with_item` node (a sibling of the `with`
        // body's `block`, per tree-sitter-python's grammar), so tracking
        // "are we inside a with_clause" while descending — rather than
        // text-matching the call's own source text, which can never contain
        // the surrounding `with` keyword — correctly exempts it without
        // also exempting unrelated `open()` calls inside the `with` body.
        fn walk(node: &AstNode, in_with_clause: bool, out: &mut Vec<Finding>) {
            let kind_str = match node.kind() {
                NodeKind::Other(k) => k.as_ref().to_string(),
                _ => String::new(),
            };

            if !in_with_clause && *node.kind() == NodeKind::Call {
                if let Some(fn_node) = node.first_child() {
                    if fn_node.text() == "open" {
                        out.push(Finding::new(
                            "File opened with `open()` outside a `with` context manager. Use `with open(...) as f:` to prevent unclosed file descriptor leaks.",
                            node.span(),
                        ));
                    }
                }
            }

            let child_in_with_clause =
                in_with_clause || kind_str == "with_clause" || kind_str == "with_item";
            for child in node.children() {
                walk(child, child_in_with_clause, out);
            }
        }

        walk(ast, false, &mut findings);
        findings
    }
}

#[cfg(test)]
mod tests {
    use vord_rules_engine::AstParser;

    use super::*;

    fn check(code: &str) -> Vec<Finding> {
        let file = SourceFile::new("t.py", code, LanguageIdentifier::python()).unwrap();
        let ast = vord_parser_python::PythonParser::new()
            .parse(&file)
            .unwrap();
        UnclosedOpenFileRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_bare_open() {
        let findings = check("f = open(\"file.txt\")\n");
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn ignores_open_inside_a_with_statement() {
        assert!(check("with open(\"file.txt\") as f:\n    f.read()\n").is_empty());
    }

    #[test]
    fn still_flags_a_bare_open_inside_a_with_statements_body() {
        let code = "with open(\"a.txt\") as f:\n    g = open(\"b.txt\")\n    g.read()\n";
        let findings = check(code);
        assert_eq!(findings.len(), 1);
    }
}
