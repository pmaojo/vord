//! Rule: flags a query/ORM-shaped call (`.query(`, `.execute(`, `.find(`,
//! `->query(`, ...) inside the body of a `for`/`while`/`foreach` loop — the
//! classic N+1 pattern of issuing one round-trip per iteration instead of
//! batching. Purely syntactic (matches on the call's method name, no type
//! resolution), so it applies across TypeScript, Python and PHP alike.

use yunq_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use yunq_rules_engine::{Finding, Rule, RuleId, Severity};

fn other_kind_name(node: &AstNode) -> Option<&str> {
    match node.kind() {
        NodeKind::Other(name) => Some(name.as_ref()),
        _ => None,
    }
}

const LOOP_KINDS: &[&str] = &[
    "for_statement",
    "for_in_statement",
    "foreach_statement",
    "while_statement",
    "do_statement",
];

const BODY_KINDS: &[&str] = &["statement_block", "block", "compound_statement"];

const QUERY_METHOD_NAMES: &[&str] = &[
    "query", "execute", "find", "findOne", "findMany", "findAll", "fetchAll", "fetchone",
    "fetchall", "select",
];

fn is_loop(node: &AstNode) -> bool {
    other_kind_name(node).is_some_and(|k| LOOP_KINDS.contains(&k))
}

fn is_arguments_wrapper(node: &AstNode) -> bool {
    other_kind_name(node).is_some_and(|k| k == "arguments" || k == "argument_list")
}

/// The loop's body block, if its very last child is one — every grammar
/// this rule targets places the body last, after any init/test/update
/// clauses (see the AST dumps this rule was built against: TS
/// `for`/`for_in`/`while`, Python `for`/`while`, PHP
/// `for`/`foreach`/`while`).
fn loop_body(loop_node: &AstNode) -> Option<&AstNode> {
    let body = loop_node.children().last()?;
    other_kind_name(body)
        .is_some_and(|k| BODY_KINDS.contains(&k))
        .then_some(body)
}

/// A `Call`'s callee and argument nodes, regardless of whether the callee is
/// a neutral `MemberAccess` (TS/Python `a.b(...)`) or PHP's flattened
/// `member_call_expression` (`[receiver, method_name, arguments]`) — in
/// both layouts it's the node directly before the arguments wrapper.
fn call_parts(call: &AstNode) -> Option<(&AstNode, &[AstNode])> {
    let children = call.children();
    let args_idx = children.iter().position(is_arguments_wrapper)?;
    let callee = args_idx.checked_sub(1).map(|i| &children[i])?;
    Some((callee, children[args_idx].children()))
}

fn method_name(callee: &AstNode) -> Option<String> {
    match callee.kind() {
        NodeKind::Identifier => Some(callee.text().to_string()),
        NodeKind::MemberAccess => callee
            .children()
            .iter()
            .rev()
            .find(|c| *c.kind() == NodeKind::Identifier)
            .map(|c| c.text().to_string()),
        _ => None,
    }
}

/// `.find(callback)` (`Array.prototype.find`) is the main false-positive
/// source for the `find` name: a real query-style `find` takes an id or
/// filter value, not a closure, so a sole function-shaped argument rules
/// the call out. Arrow functions map to the neutral `NodeKind::FunctionDef`
/// (confirmed against the real TypeScript grammar); PHP/Python closures
/// without a neutral mapping fall back to their raw grammar kind name.
fn has_closure_argument(args: &[AstNode]) -> bool {
    args.len() == 1
        && (*args[0].kind() == NodeKind::FunctionDef
            || other_kind_name(&args[0]).is_some_and(|k| k.contains("function") || k == "lambda"))
}

fn is_query_like_call(call: &AstNode) -> bool {
    let Some((callee, args)) = call_parts(call) else {
        return false;
    };
    let Some(name) = method_name(callee) else {
        return false;
    };
    QUERY_METHOD_NAMES.contains(&name.as_str()) && !has_closure_argument(args)
}

/// Collects query-like `Call`s reachable from `node` without descending
/// into a nested loop's own body — that loop reports its calls itself when
/// `ast.descendants()` reaches it, so descending here too would double-count.
fn collect_query_calls<'a>(node: &'a AstNode, out: &mut Vec<&'a AstNode>) {
    for child in node.children() {
        if is_loop(child) {
            continue;
        }
        if *child.kind() == NodeKind::Call && is_query_like_call(child) {
            out.push(child);
        }
        collect_query_calls(child, out);
    }
}

pub struct DbCallInLoopRule {
    id: RuleId,
}

impl DbCallInLoopRule {
    pub fn new() -> Self {
        Self {
            id: RuleId::new("smells:db-call-in-loop").expect("valid rule id"),
        }
    }
}

impl Default for DbCallInLoopRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for DbCallInLoopRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn applies_to(&self, _language: &LanguageIdentifier) -> bool {
        true
    }

    fn default_severity(&self) -> Severity {
        Severity::Major
    }

    fn remediation_effort_minutes(&self) -> u32 {
        20
    }

    fn metadata(&self) -> yunq_rules_engine::RuleMetadata {
        yunq_rules_engine::RuleMetadata {
            description: "A query/ORM call inside a loop body issues one round-trip per iteration (N+1); batch it into a single query outside the loop.".into(),
            tags: vec!["performance".into(), "n-plus-one".into()],
            cwe: None,
            produces_hotspots: false,
        }
    }

    fn check(&self, file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        if yunq_rules_engine::is_test_only_path(file.path()) {
            return Vec::new();
        }
        ast.descendants()
            .filter(|n| is_loop(n))
            .filter_map(loop_body)
            .flat_map(|body| {
                let mut calls = Vec::new();
                collect_query_calls(body, &mut calls);
                calls
            })
            .map(|call| {
                Finding::new(
                    "query-like call inside a loop issues one round-trip per iteration (N+1); batch it into a single query outside the loop",
                    call.span(),
                )
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use yunq_rules_engine::AstParser;

    use super::*;

    fn findings_ts(code: &str) -> Vec<Finding> {
        let file = SourceFile::new("t.ts", code, LanguageIdentifier::typescript()).unwrap();
        let ast = yunq_parser_typescript::TypeScriptParser::new()
            .parse(&file)
            .unwrap();
        DbCallInLoopRule::new().check(&file, &ast)
    }

    fn findings_py(code: &str) -> Vec<Finding> {
        let file = SourceFile::new("t.py", code, LanguageIdentifier::python()).unwrap();
        let ast = yunq_parser_python::PythonParser::new()
            .parse(&file)
            .unwrap();
        DbCallInLoopRule::new().check(&file, &ast)
    }

    fn findings_php(code: &str) -> Vec<Finding> {
        let file = SourceFile::new("t.php", code, LanguageIdentifier::php()).unwrap();
        let ast = yunq_parser_php::PhpParser::new().parse(&file).unwrap();
        DbCallInLoopRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_query_call_in_for_of_loop_ts() {
        let findings = findings_ts(
            "for (const id of ids) {\n  const row = await db.query(\"SELECT * FROM t WHERE id = ?\", [id]);\n}\n",
        );
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn flags_execute_call_in_c_style_for_loop_ts() {
        let findings = findings_ts("for (let i = 0; i < 10; i++) {\n  db.execute(i);\n}\n");
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn allows_array_find_with_callback_in_loop_ts() {
        let findings = findings_ts(
            "for (const id of ids) {\n  const item = items.find(x => x.id === id);\n}\n",
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn allows_unrelated_call_in_loop_ts() {
        let findings = findings_ts("for (const id of ids) {\n  console.log(id);\n}\n");
        assert!(findings.is_empty());
    }

    #[test]
    fn allows_query_call_outside_a_loop_ts() {
        let findings = findings_ts("const row = await db.query(\"SELECT 1\");\n");
        assert!(findings.is_empty());
    }

    #[test]
    fn does_not_flag_while_test_condition_as_in_body_ts() {
        let findings =
            findings_ts("while (cursor.hasNext()) {\n  console.log(cursor.next());\n}\n");
        assert!(findings.is_empty());
    }

    #[test]
    fn nested_loop_query_call_is_reported_once_ts() {
        let findings = findings_ts(
            "for (const id of ids) {\n  for (const sub of subIds) {\n    db.query(sub);\n  }\n}\n",
        );
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn flags_query_call_in_for_loop_python() {
        let findings = findings_py(
            "for id in ids:\n    row = db.query(\"SELECT * FROM t WHERE id = ?\", [id])\n",
        );
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn flags_query_call_in_while_loop_python() {
        let findings = findings_py("while has_more():\n    row = repo.findOne(next_id())\n");
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn flags_query_call_in_foreach_loop_php() {
        let code = "<?php\nforeach ($ids as $id) {\n    $row = $db->query(\"SELECT * FROM t WHERE id = ?\");\n}\n";
        assert_eq!(findings_php(code).len(), 1);
    }

    #[test]
    fn allows_unrelated_call_in_php_loop() {
        let code = "<?php\nforeach ($ids as $id) {\n    error_log($id);\n}\n";
        assert!(findings_php(code).is_empty());
    }
}
