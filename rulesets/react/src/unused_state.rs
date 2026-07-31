//! Rule: state that's written but never read — a `useState` binding whose
//! getter value is never referenced again in its component, or a class
//! component's `this.state` field that's initialized but never accessed via
//! `this.state.<field>`. Either way, the state exists but the render output
//! (or any other logic) never depends on it, which is either dead code or a
//! bug where the intended read was forgotten.
//!
//! Needs the same same-file scope tracking `react:exhaustive-deps` uses (to
//! scope "never referenced" to the right component, not the whole file) for
//! the hook half, and `yunq_symbols`'s class-field extraction idea (applied
//! directly here, since a class component's `state` object literal isn't a
//! declared *field with a type* so much as an object-literal-shaped
//! constructor argument — a narrower shape than `ClassRegistry` models) for
//! the class-component half.

use yunq_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use yunq_rules_engine::{Finding, IssueType, Rule, RuleId, RuleMetadata, Severity};

use crate::common::{hook_call_name, is_other};

// ---- Hook-based state (`useState`) ---------------------------------------

/// The state getter's name from `const [name, setName] = useState(...)`, if
/// `decl` has that shape.
fn use_state_getter(decl: &AstNode) -> Option<&AstNode> {
    let pattern = decl
        .first_child()
        .filter(|c| is_other(c, "array_pattern"))?;
    let getter = pattern
        .children()
        .first()
        .filter(|c| *c.kind() == NodeKind::Identifier)?;
    let call = decl
        .children()
        .iter()
        .find(|c| *c.kind() == NodeKind::Call)?;
    (hook_call_name(call) == Some("useState")).then_some(getter)
}

fn check_use_state_decl(decl: &AstNode, component: &AstNode, findings: &mut Vec<Finding>) {
    let Some(getter) = use_state_getter(decl) else {
        return;
    };
    let name = getter.text();
    let occurrences = component
        .descendants()
        .filter(|n| *n.kind() == NodeKind::Identifier && n.text() == name)
        .count();
    if occurrences <= 1 {
        findings.push(Finding::new(
            format!(
                "`{name}` is bound via `useState` but never read again in this component — either the state is dead code, or the intended read was never written"
            ),
            decl.span(),
        ));
    }
}

/// Tracks the nearest enclosing `FunctionDef` (the component a state
/// declaration/class is textually inside — or, for a class component, the
/// class node itself, used the same way as the "search scope") while
/// walking the whole file once.
fn walk<'a>(node: &'a AstNode, enclosing: Option<&'a AstNode>, findings: &mut Vec<Finding>) {
    if *node.kind() == NodeKind::VariableDecl {
        if let Some(component) = enclosing {
            check_use_state_decl(node, component, findings);
        }
    }
    if is_other(node, "class_declaration") {
        check_class_state(node, findings);
    }
    let next_enclosing = if *node.kind() == NodeKind::FunctionDef {
        Some(node)
    } else {
        enclosing
    };
    for child in node.children() {
        walk(child, next_enclosing, findings);
    }
}

// ---- Class-component state (`this.state`) --------------------------------

/// Whether `class_decl`'s superclass looks like a React component base
/// (`Component`, `PureComponent`, `React.Component`, ...) — the same
/// "match by simple name" convention `yunq_symbols::classes` uses for
/// superclass resolution generally, applied inline here since this rule
/// only needs the one substring check, not a full registry.
fn extends_react_component(class_decl: &AstNode) -> bool {
    class_decl
        .children()
        .iter()
        .find(|c| is_other(c, "class_heritage"))
        .is_some_and(|h| h.text().contains("Component"))
}

/// Every key of an object-literal (`{ a: 1, b: 2 }` or shorthand `{ a, b }`)
/// node's direct entries.
fn object_literal_keys(object: &AstNode) -> Vec<&AstNode> {
    object
        .children()
        .iter()
        .filter_map(|entry| match entry.kind() {
            NodeKind::Identifier => Some(entry), // shorthand `{ a }`
            NodeKind::Other(k) if k.as_ref() == "pair" => entry
                .first_child()
                .filter(|c| *c.kind() == NodeKind::Identifier),
            _ => None,
        })
        .collect()
}

/// Every state key initialized by this class: a `state = {...}` class
/// field, and/or `this.state = {...}` assignment(s) anywhere in the class
/// (typically the constructor).
fn initial_state_keys(class_decl: &AstNode) -> Vec<&AstNode> {
    let mut keys = Vec::new();
    for field in class_decl.descendants().filter(
        |n| matches!(n.kind(), NodeKind::Other(k) if k.as_ref().ends_with("field_definition")),
    ) {
        if field
            .first_child()
            .is_some_and(|n| *n.kind() == NodeKind::Identifier && n.text() == "state")
        {
            if let Some(object) = field.children().get(1).filter(|c| is_other(c, "object")) {
                keys.extend(object_literal_keys(object));
            }
        }
    }
    for assignment in class_decl
        .descendants()
        .filter(|n| *n.kind() == NodeKind::Assignment)
    {
        let Some(target) = assignment
            .first_child()
            .filter(|c| *c.kind() == NodeKind::MemberAccess)
        else {
            continue;
        };
        if target.text() != "this.state" {
            continue;
        }
        if let Some(object) = assignment
            .children()
            .get(1)
            .filter(|c| is_other(c, "object"))
        {
            keys.extend(object_literal_keys(object));
        }
    }
    keys
}

/// Whether `key` is read anywhere in the class via `this.state.<key>` (a
/// member access chained off exactly `this.state`) or destructured directly
/// off it (`const { key } = this.state`).
fn state_key_is_read(class_decl: &AstNode, key: &str) -> bool {
    let via_member_access = class_decl.descendants().any(|n| {
        *n.kind() == NodeKind::MemberAccess
            && n.first_child()
                .is_some_and(|base| base.text() == "this.state")
            && n.children()
                .get(1)
                .is_some_and(|prop| *prop.kind() == NodeKind::Identifier && prop.text() == key)
    });
    if via_member_access {
        return true;
    }
    class_decl.descendants().any(|n| {
        *n.kind() == NodeKind::VariableDecl
            && n.children()
                .get(1)
                .is_some_and(|rhs| rhs.text() == "this.state")
            && n.first_child().is_some_and(|pattern| {
                is_other(pattern, "object_pattern")
                    && pattern
                        .descendants()
                        .any(|leaf| *leaf.kind() == NodeKind::Identifier && leaf.text() == key)
            })
    })
}

fn check_class_state(class_decl: &AstNode, findings: &mut Vec<Finding>) {
    if !extends_react_component(class_decl) {
        return;
    }
    let mut seen = std::collections::BTreeSet::new();
    for key_node in initial_state_keys(class_decl) {
        let key = key_node.text();
        if !seen.insert(key.to_string()) {
            continue;
        }
        if !state_key_is_read(class_decl, key) {
            findings.push(Finding::new(
                format!(
                    "`this.state.{key}` is initialized but never read via `this.state.{key}` (or destructured from `this.state`) anywhere in this component"
                ),
                key_node.span(),
            ));
        }
    }
}

pub struct UnusedStateRule {
    id: RuleId,
}

impl UnusedStateRule {
    pub fn new() -> Self {
        Self {
            id: RuleId::new("react:unused-state").expect("valid rule id"),
        }
    }
}

impl Default for UnusedStateRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for UnusedStateRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn applies_to(&self, lang: &LanguageIdentifier) -> bool {
        *lang == LanguageIdentifier::typescript()
    }

    fn default_severity(&self) -> Severity {
        Severity::Minor
    }

    fn issue_type(&self) -> IssueType {
        IssueType::CodeSmell
    }

    fn metadata(&self) -> RuleMetadata {
        RuleMetadata {
            description: "A `useState` value or class-component `this.state` field is written but never read anywhere in its component.".into(),
            tags: vec!["react".into(), "hooks".into(), "dead-code".into()],
            cwe: None,
            produces_hotspots: false,
        }
    }

    fn check(&self, _file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        let mut findings = Vec::new();
        walk(ast, None, &mut findings);
        findings
    }
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
        UnusedStateRule::new().check(&file, &ast)
    }

    #[test]
    fn allows_use_state_value_read_inside_a_nested_event_handler() {
        let findings = check(
            "function Comp() {\n  const [count, setCount] = useState(0);\n  return <button onClick={() => setCount(count + 1)} />;\n}\n",
        );
        // `count` IS read here (inside the onClick handler expression) —
        // this should be silent. Kept as the negative twin of the next test.
        assert!(findings.is_empty(), "{findings:?}");
    }

    #[test]
    fn flags_use_state_value_truly_never_read() {
        let findings = check(
            "function Comp() {\n  const [count, setCount] = useState(0);\n  setCount(1);\n  return null;\n}\n",
        );
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("`count`"));
    }

    #[test]
    fn allows_use_state_value_read_in_jsx() {
        let findings = check(
            "function Comp() {\n  const [count, setCount] = useState(0);\n  return <div>{count}</div>;\n}\n",
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn scopes_unused_state_check_per_component() {
        // `count` is unused in `A` but a same-named, unrelated `count` is
        // used in `B` — each component's state must be checked in its own
        // scope, not against the whole file's identifier soup.
        let findings = check(
            "function A() {\n  const [count, setCount] = useState(0);\n  return null;\n}\nfunction B() {\n  const [count, setCount] = useState(0);\n  return <div>{count}</div>;\n}\n",
        );
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn flags_class_state_field_never_read() {
        let findings = check(
            "class C extends React.Component {\n  state = { count: 0 };\n  render() {\n    return <div>hi</div>;\n  }\n}\n",
        );
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("count"));
    }

    #[test]
    fn allows_class_state_field_read_via_this_state() {
        let findings = check(
            "class C extends React.Component {\n  state = { count: 0 };\n  render() {\n    return <div>{this.state.count}</div>;\n  }\n}\n",
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn allows_class_state_field_read_via_destructuring() {
        let findings = check(
            "class C extends React.Component {\n  state = { count: 0 };\n  render() {\n    const { count } = this.state;\n    return <div>{count}</div>;\n  }\n}\n",
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn ignores_state_field_on_a_non_component_class() {
        let findings = check("class Plain {\n  state = { count: 0 };\n}\n");
        assert!(findings.is_empty());
    }

    #[test]
    fn constructor_this_state_assignment_is_tracked_too() {
        let findings = check(
            "class C extends React.Component {\n  constructor(props) {\n    super(props);\n    this.state = { count: 0 };\n  }\n  render() {\n    return <div>hi</div>;\n  }\n}\n",
        );
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("count"));
    }
}
