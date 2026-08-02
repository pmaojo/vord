//! Minimal intra-file taint analysis over the neutral AST.
//!
//! Tracks values flowing from configured *source markers* (e.g.
//! `process.argv`) through variable declarations and assignments into
//! configured *sink callees* (e.g. `eval`), and reports each reachable
//! source→sink flow with a human-readable trace.
//!
//! Relies on the structural contracts documented on
//! [`vord_ast::NodeKind`]: `VariableDecl`/`Assignment` start with their
//! target identifier, `Call` starts with its callee.

mod cross;
pub mod module_graph;

pub use cross::{CrossFileFlow, CrossFileTaint};

use std::collections::HashMap;

use vord_ast::{AstNode, NodeKind, Span};

/// What taints (sources), what must not receive taint (sinks), and what
/// strips taint from a value (sanitizers).
#[derive(Clone, Debug, Default)]
pub struct TaintConfig {
    source_markers: Vec<String>,
    sink_callees: Vec<String>,
    sanitizer_callees: Vec<String>,
}

impl TaintConfig {
    pub fn new() -> Self {
        Self::default()
    }

    /// Any expression whose text contains this marker is considered tainted.
    pub fn with_source_marker(mut self, marker: impl Into<String>) -> Self {
        self.source_markers.push(marker.into());
        self
    }

    /// Calls to this callee name must not receive tainted arguments.
    pub fn with_sink(mut self, callee: impl Into<String>) -> Self {
        self.sink_callees.push(callee.into());
        self
    }

    /// Calls to this callee name are trusted to strip taint from their
    /// result: a call `sanitize(tainted)` is treated as clean, regardless of
    /// what flows into its arguments.
    pub fn with_sanitizer(mut self, callee: impl Into<String>) -> Self {
        self.sanitizer_callees.push(callee.into());
        self
    }

    pub fn source_markers(&self) -> &[String] {
        &self.source_markers
    }

    pub fn sink_callees(&self) -> &[String] {
        &self.sink_callees
    }

    pub fn sanitizer_callees(&self) -> &[String] {
        &self.sanitizer_callees
    }
}

/// One source→sink flow found in a file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TaintFlow {
    pub source: String,
    pub sink: String,
    pub sink_span: Span,
    pub trace: Vec<String>,
}

#[derive(Clone, Debug)]
struct TaintedVar {
    source: String,
    trace: Vec<String>,
}

pub struct TaintAnalysis {
    config: TaintConfig,
}

impl TaintAnalysis {
    pub fn new(config: TaintConfig) -> Self {
        Self { config }
    }

    pub fn find_flows(&self, ast: &AstNode) -> Vec<TaintFlow> {
        let tainted = self.propagate(ast);
        let mut flows = Vec::new();

        for call in ast.descendants().filter(|n| *n.kind() == NodeKind::Call) {
            let Some(callee) = call.first_child() else { continue };
            let callee_name = Self::callee_name(callee);
            if !self.config.sink_callees.iter().any(|s| s == &callee_name) {
                continue;
            }
            for arg in &call.children()[1..] {
                if let Some(marker) = self.direct_source(arg) {
                    flows.push(TaintFlow {
                        source: marker.clone(),
                        sink: callee_name.clone(),
                        sink_span: call.span(),
                        trace: vec![format!("`{marker}` flows directly into `{callee_name}`")],
                    });
                } else if let Some(var) = self.tainted_identifier(arg, &tainted) {
                    let mut trace = tainted[&var].trace.clone();
                    trace.push(format!("`{var}` reaches sink `{callee_name}`"));
                    flows.push(TaintFlow {
                        source: tainted[&var].source.clone(),
                        sink: callee_name.clone(),
                        sink_span: call.span(),
                        trace,
                    });
                }
            }
        }
        flows
    }

    /// Attempts to taint `node`'s declared/assigned identifier from either a
    /// direct source marker or an already-tainted identifier in its value
    /// expression(s). Returns whether it newly tainted anything — `false`
    /// when the target isn't a plain identifier, is already tainted, or
    /// none of its values are tainted (yet).
    fn try_taint_declaration(&self, node: &AstNode, tainted: &mut HashMap<String, TaintedVar>) -> bool {
        let Some(target) = node.first_child() else { return false };
        if *target.kind() != NodeKind::Identifier {
            return false;
        }
        let name = target.text().to_string();
        if tainted.contains_key(&name) {
            return false;
        }
        for value in &node.children()[1..] {
            if let Some(marker) = self.direct_source(value) {
                tainted.insert(
                    name.clone(),
                    TaintedVar { source: marker.clone(), trace: vec![format!("`{name}` tainted by `{marker}`")] },
                );
                return true;
            }
            if let Some(origin) = self.tainted_identifier(value, tainted) {
                let parent = tainted[&origin].clone();
                let mut trace = parent.trace;
                trace.push(format!("`{name}` tainted via `{origin}`"));
                tainted.insert(name.clone(), TaintedVar { source: parent.source, trace });
                return true;
            }
        }
        false
    }

    /// Fixpoint propagation of taint through declarations and assignments.
    fn propagate(&self, ast: &AstNode) -> HashMap<String, TaintedVar> {
        let mut tainted: HashMap<String, TaintedVar> = HashMap::new();
        loop {
            let mut changed = false;
            for node in ast
                .descendants()
                .filter(|n| matches!(n.kind(), NodeKind::VariableDecl | NodeKind::Assignment))
            {
                changed |= self.try_taint_declaration(node, &mut tainted);
            }
            if !changed {
                return tainted;
            }
        }
    }

    /// Marker contained anywhere in this expression subtree, if any. A call
    /// to a configured sanitizer cleanses its whole subtree.
    fn direct_source(&self, expr: &AstNode) -> Option<&String> {
        if self.is_sanitized(expr) {
            return None;
        }
        self.config.source_markers.iter().find(|m| expr.subtree_contains_text(m))
    }

    /// A tainted identifier referenced anywhere in this expression subtree,
    /// not counting identifiers that only appear inside a sanitizer call's
    /// arguments.
    fn tainted_identifier(
        &self,
        expr: &AstNode,
        tainted: &HashMap<String, TaintedVar>,
    ) -> Option<String> {
        if self.is_sanitized(expr) {
            return None;
        }
        if *expr.kind() == NodeKind::Identifier && tainted.contains_key(expr.text()) {
            return Some(expr.text().to_string());
        }
        expr.children().iter().find_map(|child| self.tainted_identifier(child, tainted))
    }

    /// Whether `node` is a call to a configured sanitizer — trusted to
    /// return a clean value regardless of what flows into its arguments.
    fn is_sanitized(&self, node: &AstNode) -> bool {
        *node.kind() == NodeKind::Call
            && node.first_child().is_some_and(|callee| self.is_sanitizer(callee))
    }

    fn is_sanitizer(&self, callee: &AstNode) -> bool {
        let name = Self::callee_name(callee);
        self.config.sanitizer_callees.iter().any(|s| *s == name || callee.text().ends_with(s.as_str()))
    }

    /// For `MemberAccess` callees like `child_process.execSync`, sinks match
    /// on the final segment; plain identifiers match on their text.
    fn callee_name(callee: &AstNode) -> String {
        match callee.kind() {
            NodeKind::MemberAccess => callee
                .children()
                .iter()
                .rev()
                .find(|c| *c.kind() == NodeKind::Identifier)
                .map(|c| c.text().to_string())
                .unwrap_or_else(|| callee.text().to_string()),
            _ => callee.text().to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn span() -> Span {
        Span::new(1, 1, 1, 10)
    }

    fn ident(name: &str) -> AstNode {
        AstNode::new(NodeKind::Identifier, span(), name, vec![])
    }

    fn decl(name: &str, value: AstNode) -> AstNode {
        let text = format!("{name} = {}", value.text());
        AstNode::new(NodeKind::VariableDecl, span(), text, vec![ident(name), value])
    }

    fn call(callee: &str, arg: AstNode) -> AstNode {
        let text = format!("{callee}({})", arg.text());
        AstNode::new(NodeKind::Call, span(), text, vec![ident(callee), arg])
    }

    fn unit(children: Vec<AstNode>) -> AstNode {
        AstNode::new(NodeKind::SourceUnit, span(), "", children)
    }

    fn config() -> TaintConfig {
        TaintConfig::new().with_source_marker("process.argv").with_sink("eval")
    }

    #[test]
    fn detects_flow_through_a_variable() {
        let source_expr =
            AstNode::new(NodeKind::MemberAccess, span(), "process.argv", vec![]);
        let ast = unit(vec![decl("input", source_expr), call("eval", ident("input"))]);

        let flows = TaintAnalysis::new(config()).find_flows(&ast);
        assert_eq!(flows.len(), 1);
        assert_eq!(flows[0].sink, "eval");
        assert_eq!(flows[0].source, "process.argv");
        assert_eq!(flows[0].trace.len(), 2);
    }

    #[test]
    fn detects_transitive_flow_and_direct_flow() {
        let source_expr =
            AstNode::new(NodeKind::MemberAccess, span(), "process.argv", vec![]);
        let ast = unit(vec![
            decl("a", source_expr.clone()),
            decl("b", ident("a")),
            call("eval", ident("b")),
            call("eval", source_expr),
        ]);

        let flows = TaintAnalysis::new(config()).find_flows(&ast);
        assert_eq!(flows.len(), 2);
        assert_eq!(flows[0].trace.len(), 3); // a → b → sink
    }

    #[test]
    fn clean_variables_do_not_flow() {
        let ast = unit(vec![
            decl("safe", AstNode::new(NodeKind::StringLiteral, span(), "\"hi\"", vec![])),
            call("eval", ident("safe")),
        ]);
        assert!(TaintAnalysis::new(config()).find_flows(&ast).is_empty());
    }

    #[test]
    fn member_access_callee_matches_last_segment() {
        let source_expr =
            AstNode::new(NodeKind::MemberAccess, span(), "process.argv", vec![]);
        let callee = AstNode::new(
            NodeKind::MemberAccess,
            span(),
            "cp.execSync",
            vec![ident("cp"), ident("execSync")],
        );
        let sink_call = AstNode::new(
            NodeKind::Call,
            span(),
            "cp.execSync(x)",
            vec![callee, ident("x")],
        );
        let ast = unit(vec![decl("x", source_expr), sink_call]);

        let cfg = TaintConfig::new().with_source_marker("process.argv").with_sink("execSync");
        let flows = TaintAnalysis::new(cfg).find_flows(&ast);
        assert_eq!(flows.len(), 1);
        assert_eq!(flows[0].sink, "execSync");
    }

    fn config_with_sanitizer() -> TaintConfig {
        config().with_sanitizer("sanitize")
    }

    #[test]
    fn sanitized_value_assigned_to_a_variable_does_not_flow() {
        let source_expr = AstNode::new(NodeKind::MemberAccess, span(), "process.argv", vec![]);
        let ast = unit(vec![
            decl("input", call("sanitize", source_expr)),
            call("eval", ident("input")),
        ]);

        assert!(TaintAnalysis::new(config_with_sanitizer()).find_flows(&ast).is_empty());
    }

    #[test]
    fn sanitized_value_passed_directly_to_a_sink_does_not_flow() {
        let source_expr = AstNode::new(NodeKind::MemberAccess, span(), "process.argv", vec![]);
        let ast = unit(vec![call("eval", call("sanitize", source_expr))]);

        assert!(TaintAnalysis::new(config_with_sanitizer()).find_flows(&ast).is_empty());
    }

    #[test]
    fn unsanitized_flow_is_still_detected_alongside_a_sanitizer() {
        let source_expr = AstNode::new(NodeKind::MemberAccess, span(), "process.argv", vec![]);
        let ast = unit(vec![decl("input", source_expr), call("eval", ident("input"))]);

        let flows = TaintAnalysis::new(config_with_sanitizer()).find_flows(&ast);
        assert_eq!(flows.len(), 1);
    }
}
