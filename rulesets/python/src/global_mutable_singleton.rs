//! Rule: flags a module-level variable initialized to a mutable literal or
//! constructor (`_cache = {}`, `_registry = []`) that some function in the
//! same file also declares with `global` and rebinds or mutates. That
//! combination is the mutable global singleton anti-pattern: shared,
//! order-dependent state with no owner, invisible in every function
//! signature that touches it, and unsafe to use from more than one thread
//! without external locking.

use vord_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use vord_rules_engine::{Finding, IssueType, Rule, RuleId, Severity};

use crate::common::other_kind_name;

const MUTABLE_LITERAL_KINDS: &[&str] = &[
    "list",
    "dictionary",
    "set",
    "list_comprehension",
    "dictionary_comprehension",
    "set_comprehension",
];
const MUTABLE_CTORS: &[&str] = &["list", "dict", "set"];

fn is_mutable_value(value: &AstNode) -> bool {
    if other_kind_name(value).is_some_and(|k| MUTABLE_LITERAL_KINDS.contains(&k)) {
        return true;
    }
    value.kind() == &NodeKind::Call
        && value
            .first_child()
            .is_some_and(|callee| MUTABLE_CTORS.contains(&callee.text()))
}

fn module_level_assignments(source_unit: &AstNode) -> impl Iterator<Item = &AstNode> {
    source_unit
        .children()
        .iter()
        .filter_map(|stmt| {
            (other_kind_name(stmt) == Some("expression_statement"))
                .then(|| stmt.first_child())
                .flatten()
        })
        .filter(|n| n.kind() == &NodeKind::Assignment)
}

const MUTATING_METHODS: &[&str] = &[
    "append",
    "extend",
    "update",
    "pop",
    "remove",
    "add",
    "clear",
    "insert",
    "discard",
    "popitem",
    "setdefault",
    "sort",
    "reverse",
];

/// Whether `body` actually rebinds or mutates `name` somewhere — a direct
/// reassignment (`name = ...`), a subscript/attribute write
/// (`name[k] = v`, `name.attr = v`), a known mutating method call
/// (`name.append(...)`), an augmented assignment (`name += ...`), or
/// `del name[...]`. Merely declaring `global name` to *read* module state
/// (`global _cache; return _cache.get(key)`) does none of these and is not
/// the mutable-singleton anti-pattern this rule targets.
fn rebinds_or_mutates(body: &AstNode, name: &str) -> bool {
    let structural = body.descendants().any(|n| {
        if n.kind() == &NodeKind::Assignment {
            if let Some(target) = n.children().first() {
                if target.kind() == &NodeKind::Identifier && target.text() == name {
                    return true;
                }
                if target.kind() == &NodeKind::MemberAccess
                    && target.first_child().is_some_and(|obj| obj.text() == name)
                {
                    return true;
                }
            }
        }
        if n.kind() == &NodeKind::Call {
            if let Some(callee) = n.first_child() {
                if callee.kind() == &NodeKind::MemberAccess {
                    let object_matches =
                        callee.first_child().is_some_and(|obj| obj.text() == name);
                    let method_matches = callee
                        .children()
                        .last()
                        .is_some_and(|m| MUTATING_METHODS.contains(&m.text()));
                    if object_matches && method_matches {
                        return true;
                    }
                }
            }
        }
        false
    });
    // Augmented assignment (`name += ...`) and `del name[...]` have no
    // dedicated structural check here; a conservative textual fallback
    // still catches them without needing a new node-kind mapping.
    structural
        || body.text().contains(&format!("{name} +="))
        || body.text().contains(&format!("{name} -="))
        || body.text().contains(&format!("del {name}"))
}

/// Names any function in this file declares `global` for *and actually
/// rebinds or mutates* somewhere in its body — not just reads. Scoped per
/// function (rather than pooled file-wide) since only the declaring
/// function's own body can be checked for a matching mutation.
fn globally_declared_names(ast: &AstNode) -> Vec<&str> {
    ast.descendants()
        .filter(|n| *n.kind() == NodeKind::FunctionDef)
        .filter_map(|func| {
            let body = func.children().iter().find(|c| other_kind_name(c) == Some("block"))?;
            Some(body)
        })
        .flat_map(|body| {
            let names: Vec<&str> = body
                .descendants()
                .filter(|n| other_kind_name(n) == Some("global_statement"))
                .flat_map(|n| n.children().iter())
                .filter(|c| c.kind() == &NodeKind::Identifier)
                .map(|c| c.text())
                .collect();
            names
                .into_iter()
                .filter(move |name| rebinds_or_mutates(body, name))
        })
        .collect()
}

pub struct GlobalMutableSingletonRule {
    id: RuleId,
}

impl GlobalMutableSingletonRule {
    pub fn new() -> Self {
        Self {
            id: RuleId::new("python:global-mutable-singleton").expect("valid rule id"),
        }
    }
}

impl Default for GlobalMutableSingletonRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for GlobalMutableSingletonRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn applies_to(&self, lang: &LanguageIdentifier) -> bool {
        *lang == LanguageIdentifier::python()
    }

    fn default_severity(&self) -> Severity {
        Severity::Major
    }

    fn issue_type(&self) -> IssueType {
        IssueType::CodeSmell
    }

    fn remediation_effort_minutes(&self) -> u32 {
        30
    }

    fn metadata(&self) -> vord_rules_engine::RuleMetadata {
        vord_rules_engine::RuleMetadata {
            description: "A module-level mutable container rebound through `global` by some function is shared, order-dependent state with no owner and no thread safety; wrap it in a class or pass it explicitly instead.".into(),
            tags: vec!["maintainability".into(), "concurrency".into(), "python-idiom".into()],
            cwe: None,
            produces_hotspots: false,
        }
    }

    fn check(&self, _file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        let global_names = globally_declared_names(ast);
        if global_names.is_empty() {
            return Vec::new();
        }
        module_level_assignments(ast)
            .filter(|assignment| {
                assignment
                    .children()
                    .first()
                    .is_some_and(|target| target.kind() == &NodeKind::Identifier && global_names.contains(&target.text()))
            })
            .filter(|assignment| assignment.children().get(1).is_some_and(is_mutable_value))
            .map(|assignment| Finding::new("module-level mutable value is rebound through `global` elsewhere in this file; that's shared, order-dependent state with no owner. Wrap it in a class or pass it explicitly instead", assignment.span()))
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
        GlobalMutableSingletonRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_module_dict_rebound_through_global() {
        let code = "_cache = {}\n\ndef reset():\n    global _cache\n    _cache = {}\n";
        assert_eq!(findings(code).len(), 1);
    }

    #[test]
    fn allows_mutable_module_value_never_declared_global() {
        let code = "_cache = {}\n\ndef read():\n    return _cache.get('x')\n";
        assert!(findings(code).is_empty());
    }

    #[test]
    fn allows_immutable_module_constant_declared_global() {
        let code = "COUNT = 0\n\ndef bump():\n    global COUNT\n    COUNT += 1\n";
        assert!(findings(code).is_empty());
    }

    /// Regression: declaring `global` to *read* a module-level dict (no
    /// reassignment, no mutation) is not the mutable-singleton
    /// anti-pattern — the message even claimed it was "rebound", which
    /// was simply false for this shape.
    #[test]
    fn allows_module_dict_declared_global_but_only_read() {
        let code = "_cache = {}\n\ndef read(key):\n    global _cache\n    return _cache.get(key)\n";
        assert!(findings(code).is_empty());
    }

    /// A mutating *method call* (`.update(...)`) through `global`, with no
    /// reassignment of the name itself, is still the same anti-pattern
    /// and must be flagged.
    #[test]
    fn flags_module_dict_mutated_via_method_call_through_global() {
        let code = "_cache = {}\n\ndef put(key, value):\n    global _cache\n    _cache.update({key: value})\n";
        assert_eq!(findings(code).len(), 1);
    }

    /// A subscript write (`_cache[key] = value`) through `global` is also
    /// a real mutation and must be flagged.
    #[test]
    fn flags_module_dict_mutated_via_subscript_through_global() {
        let code = "_cache = {}\n\ndef put(key, value):\n    global _cache\n    _cache[key] = value\n";
        assert_eq!(findings(code).len(), 1);
    }
}
