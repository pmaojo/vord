//! Inter-procedural, cross-file taint analysis.
//!
//! Two phases over the whole file set:
//! 1. **Summaries**: every named function gets a summary — which parameters
//!    flow into a sink (directly or through calls to other summarized
//!    functions), which parameters flow to its return value, and whether it
//!    returns source-tainted data. Summaries are iterated to a global
//!    fixpoint, so chains like `caller → helper → runner → sink` resolve
//!    regardless of file boundaries.
//! 2. **Emission**: each file is scanned as a whole; a call is reported when
//!    source-tainted data reaches a *summarized* call whose parameter is
//!    known to hit a sink. Direct source→sink flows inside one file are the
//!    intra-file analysis's job and are not duplicated here.
//!
//! Name resolution is intentionally simple: functions are indexed by name
//! project-wide (first definition wins). No scoping, no aliasing — a
//! heuristic that trades soundness corners for zero configuration.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use yunq_ast::{AstNode, NodeKind, Span};

use crate::TaintConfig;

/// A reported cross-file flow, ready to become a finding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CrossFileFlow {
    /// File containing the call where tainted data escapes.
    pub file: String,
    pub span: Span,
    pub message: String,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Origin {
    Param(usize),
    Source(String),
}

type Origins = BTreeSet<Origin>;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct Summary {
    /// Parameter index → human description of the sink it reaches,
    /// e.g. "`execSync` (lib.ts)".
    param_to_sink: BTreeMap<usize, String>,
    /// Parameters that flow into the return value.
    param_to_return: BTreeSet<usize>,
    /// The return value carries data from a configured source.
    returns_source: bool,
}

struct FunctionInfo<'a> {
    file: String,
    name: String,
    params: Vec<String>,
    body: &'a AstNode,
}

pub struct CrossFileTaint {
    config: TaintConfig,
}

impl CrossFileTaint {
    pub fn new(config: TaintConfig) -> Self {
        Self { config }
    }

    pub fn find_flows(&self, files: &[(&str, &AstNode)]) -> Vec<CrossFileFlow> {
        let functions = collect_functions(files);
        let mut summaries: HashMap<String, Summary> =
            functions.iter().map(|f| (f.name.clone(), Summary::default())).collect();

        // Phase 1: summaries to a global fixpoint (bounded).
        for _ in 0..10 {
            let mut changed = false;
            for function in &functions {
                let (summary, _) = self.analyze(
                    function.body,
                    &function.params,
                    &function.file,
                    &summaries,
                );
                if summaries.get(&function.name) != Some(&summary) {
                    summaries.insert(function.name.clone(), summary);
                    changed = true;
                }
            }
            if !changed {
                break;
            }
        }

        // Phase 2: whole-file emission passes (no parameters seeded).
        let mut flows: Vec<CrossFileFlow> = Vec::new();
        for (path, ast) in files {
            let (_, emissions) = self.analyze(ast, &[], path, &summaries);
            flows.extend(emissions);
        }
        flows.sort_by(|a, b| {
            (&a.file, a.span.start_line, &a.message).cmp(&(&b.file, b.span.start_line, &b.message))
        });
        flows.dedup();
        flows
    }

    /// Propagates taint through variable bindings (`VariableDecl`/
    /// `Assignment`) to a local fixpoint: repeatedly re-scans until no
    /// binding's known origins grow, so a chain like `a = b; c = a;`
    /// resolves regardless of declaration order.
    fn propagate_bindings(
        &self,
        body: &AstNode,
        tainted: &mut HashMap<String, Origins>,
        summaries: &HashMap<String, Summary>,
    ) {
        loop {
            let mut changed = false;
            for node in body
                .descendants()
                .filter(|n| matches!(n.kind(), NodeKind::VariableDecl | NodeKind::Assignment))
            {
                let Some(target) = node.first_child() else { continue };
                if *target.kind() != NodeKind::Identifier {
                    continue;
                }
                let mut origins = Origins::new();
                for value in &node.children()[1..] {
                    origins.extend(self.origins_of(value, tainted, summaries));
                }
                if origins.is_empty() {
                    continue;
                }
                let entry = tainted.entry(target.text().to_string()).or_default();
                let before = entry.len();
                entry.extend(origins);
                changed |= entry.len() != before;
            }
            if !changed {
                break;
            }
        }
    }

    /// Direct sink: only parameters feed the summary; direct source→sink
    /// stays with the intra-file analysis.
    #[allow(clippy::too_many_arguments)]
    fn record_direct_sink(
        &self,
        call: &AstNode,
        callee: &AstNode,
        name: &str,
        file: &str,
        tainted: &HashMap<String, Origins>,
        summaries: &HashMap<String, Summary>,
        summary: &mut Summary,
    ) {
        if !self.is_sink(callee) {
            return;
        }
        for arg in &call.children()[1..] {
            for origin in self.origins_of(arg, tainted, summaries) {
                if let Origin::Param(i) = origin {
                    summary.param_to_sink.entry(i).or_insert_with(|| format!("`{name}` ({file})"));
                }
            }
        }
    }

    /// Summarized call: its dangerous parameters are extended sinks — a
    /// param-origin extends this region's own summary, a source-origin
    /// emits a finding directly (the flow is complete here).
    #[allow(clippy::too_many_arguments)]
    fn record_summarized_call(
        &self,
        call: &AstNode,
        name: &str,
        file: &str,
        tainted: &HashMap<String, Origins>,
        summaries: &HashMap<String, Summary>,
        summary: &mut Summary,
        emissions: &mut Vec<CrossFileFlow>,
    ) {
        let Some(callee_summary) = summaries.get(name) else { return };
        for (arg_index, arg) in call.children()[1..].iter().enumerate() {
            let Some(sink) = callee_summary.param_to_sink.get(&arg_index) else { continue };
            for origin in self.origins_of(arg, tainted, summaries) {
                match origin {
                    Origin::Param(i) => {
                        summary.param_to_sink.entry(i).or_insert_with(|| format!("{sink} via `{name}`"));
                    }
                    Origin::Source(source) => emissions.push(CrossFileFlow {
                        file: file.to_string(),
                        span: call.span(),
                        message: format!(
                            "user input from `{source}` reaches sink {sink} through call to `{name}`"
                        ),
                    }),
                }
            }
        }
    }

    /// Call sites: builds the summary and emits cross-file flows.
    fn analyze_calls(
        &self,
        body: &AstNode,
        file: &str,
        tainted: &HashMap<String, Origins>,
        summaries: &HashMap<String, Summary>,
        summary: &mut Summary,
        emissions: &mut Vec<CrossFileFlow>,
    ) {
        for call in body.descendants().filter(|n| *n.kind() == NodeKind::Call) {
            let Some(callee) = call.first_child() else { continue };
            let name = callee_name(callee);
            self.record_direct_sink(call, callee, &name, file, tainted, summaries, summary);
            self.record_summarized_call(call, &name, file, tainted, summaries, summary, emissions);
        }
    }

    /// Returns: which taints escape through the return value.
    fn analyze_returns(
        &self,
        body: &AstNode,
        tainted: &HashMap<String, Origins>,
        summaries: &HashMap<String, Summary>,
        summary: &mut Summary,
    ) {
        for ret in body.descendants().filter(|n| match n.kind() {
            NodeKind::Other(kind) => kind.starts_with("return"),
            _ => false,
        }) {
            for origin in self.origins_of(ret, tainted, summaries) {
                match origin {
                    Origin::Param(i) => {
                        summary.param_to_return.insert(i);
                    }
                    Origin::Source(_) => summary.returns_source = true,
                }
            }
        }
    }

    /// Analyzes one region (a function body or a whole file): propagates
    /// taint through bindings, consults summaries at call sites, and returns
    /// this region's summary plus any source→summarized-sink emissions.
    fn analyze(
        &self,
        body: &AstNode,
        params: &[String],
        file: &str,
        summaries: &HashMap<String, Summary>,
    ) -> (Summary, Vec<CrossFileFlow>) {
        let mut tainted: HashMap<String, Origins> = params
            .iter()
            .enumerate()
            .map(|(i, name)| (name.clone(), BTreeSet::from([Origin::Param(i)])))
            .collect();
        self.propagate_bindings(body, &mut tainted, summaries);

        let mut summary = Summary::default();
        let mut emissions = Vec::new();
        self.analyze_calls(body, file, &tainted, summaries, &mut summary, &mut emissions);
        self.analyze_returns(body, &tainted, summaries, &mut summary);

        (summary, emissions)
    }

    /// All taint origins reaching a `Call` node: does it return
    /// source-tainted data itself, or forward one of its own tainted
    /// arguments through to its return value (per its summary)?
    fn call_origins(
        &self,
        node: &AstNode,
        tainted: &HashMap<String, Origins>,
        summaries: &HashMap<String, Summary>,
    ) -> Origins {
        let mut origins = Origins::new();
        let Some(callee) = node.first_child() else { return origins };
        let Some(summary) = summaries.get(&callee_name(callee)) else { return origins };
        if summary.returns_source {
            origins.insert(Origin::Source(format!("{}()", callee_name(callee))));
        }
        for (i, arg) in node.children()[1..].iter().enumerate() {
            if summary.param_to_return.contains(&i) {
                origins.extend(self.origins_of(arg, tainted, summaries));
            }
        }
        origins
    }

    /// All taint origins reaching an expression subtree. A call to a
    /// configured sanitizer cleanses its whole subtree: neither a source
    /// marker inside it nor taint carried by its arguments propagates out.
    fn origins_of(
        &self,
        expr: &AstNode,
        tainted: &HashMap<String, Origins>,
        summaries: &HashMap<String, Summary>,
    ) -> Origins {
        let mut origins = Origins::new();
        if self.is_sanitized(expr) {
            return origins;
        }
        for marker in self.config.source_markers() {
            if expr.subtree_contains_text(marker) {
                origins.insert(Origin::Source(marker.clone()));
            }
        }
        self.collect_unsanitized_origins(expr, tainted, summaries, &mut origins);
        origins
    }

    /// Visits `node` and its descendants for identifier/call origins,
    /// skipping any subtree rooted at a sanitizer call.
    fn collect_unsanitized_origins(
        &self,
        node: &AstNode,
        tainted: &HashMap<String, Origins>,
        summaries: &HashMap<String, Summary>,
        origins: &mut Origins,
    ) {
        match node.kind() {
            NodeKind::Identifier => {
                if let Some(known) = tainted.get(node.text()) {
                    origins.extend(known.iter().cloned());
                }
            }
            NodeKind::Call => origins.extend(self.call_origins(node, tainted, summaries)),
            _ => {}
        }
        for child in node.children() {
            if self.is_sanitized(child) {
                continue;
            }
            self.collect_unsanitized_origins(child, tainted, summaries, origins);
        }
    }

    fn is_sink(&self, callee: &AstNode) -> bool {
        let name = callee_name(callee);
        self.config.sink_callees().iter().any(|s| *s == name || callee.text().ends_with(s.as_str()))
    }

    fn is_sanitizer(&self, callee: &AstNode) -> bool {
        let name = callee_name(callee);
        self.config.sanitizer_callees().iter().any(|s| *s == name || callee.text().ends_with(s.as_str()))
    }

    /// Whether `node` is a call to a configured sanitizer — trusted to
    /// return a clean value regardless of what flows into its arguments.
    fn is_sanitized(&self, node: &AstNode) -> bool {
        *node.kind() == NodeKind::Call
            && node.first_child().is_some_and(|callee| self.is_sanitizer(callee))
    }
}

/// Callee name for matching: plain identifiers as-is; member/scoped paths by
/// their final segment (`cp.execSync` → `execSync`, `Command::new` → `new`).
fn callee_name(callee: &AstNode) -> String {
    match callee.kind() {
        NodeKind::Identifier => callee.text().to_string(),
        NodeKind::MemberAccess => callee
            .children()
            .iter()
            .rev()
            .find(|c| *c.kind() == NodeKind::Identifier)
            .map(|c| c.text().to_string())
            .unwrap_or_else(|| callee.text().to_string()),
        _ => callee
            .text()
            .rsplit(['.', ':'])
            .next()
            .unwrap_or(callee.text())
            .to_string(),
    }
}

fn collect_functions<'a>(files: &[(&'a str, &'a AstNode)]) -> Vec<FunctionInfo<'a>> {
    let mut functions = Vec::new();
    let mut seen: BTreeSet<String> = BTreeSet::new();
    for (path, ast) in files {
        for function in ast.descendants().filter(|n| *n.kind() == NodeKind::FunctionDef) {
            let Some(name_node) = function
                .children()
                .iter()
                .find(|c| *c.kind() == NodeKind::Identifier)
            else {
                continue;
            };
            let name = name_node.text().to_string();
            // First definition wins project-wide.
            if !seen.insert(name.clone()) {
                continue;
            }
            let params = function
                .children()
                .iter()
                .find(|c| matches!(c.kind(), NodeKind::Other(k) if k.contains("param")))
                .map(|p| {
                    p.descendants()
                        .filter(|n| *n.kind() == NodeKind::Identifier)
                        .map(|n| n.text().to_string())
                        .collect()
                })
                .unwrap_or_default();
            functions.push(FunctionInfo {
                file: path.to_string(),
                name,
                params,
                body: function,
            });
        }
    }
    functions
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

    fn call(callee: &str, args: Vec<AstNode>) -> AstNode {
        let mut children = vec![ident(callee)];
        children.extend(args);
        AstNode::new(NodeKind::Call, span(), format!("{callee}(...)"), children)
    }

    fn function(name: &str, params: &[&str], body: Vec<AstNode>) -> AstNode {
        let param_node = AstNode::new(
            NodeKind::Other("formal_parameters".into()),
            span(),
            params.join(", "),
            params.iter().map(|p| ident(p)).collect(),
        );
        let mut children = vec![ident(name), param_node];
        children.extend(body);
        AstNode::new(NodeKind::FunctionDef, span(), format!("function {name}"), children)
    }

    fn unit(children: Vec<AstNode>) -> AstNode {
        AstNode::new(NodeKind::SourceUnit, span(), "", children)
    }

    fn config() -> TaintConfig {
        TaintConfig::new().with_source_marker("process.argv").with_sink("execSync")
    }

    #[test]
    fn detects_flow_through_an_imported_function() {
        // lib.ts: function run(cmd) { execSync(cmd) }
        let lib = unit(vec![function("run", &["cmd"], vec![call("execSync", vec![ident("cmd")])])]);
        // main.ts: input = process.argv; run(input)
        let main = unit(vec![
            AstNode::new(
                NodeKind::VariableDecl,
                span(),
                "input = process.argv[2]",
                vec![ident("input"), AstNode::new(NodeKind::MemberAccess, span(), "process.argv[2]", vec![])],
            ),
            call("run", vec![ident("input")]),
        ]);

        let flows = CrossFileTaint::new(config())
            .find_flows(&[("lib.ts", &lib), ("main.ts", &main)]);
        assert_eq!(flows.len(), 1);
        assert_eq!(flows[0].file, "main.ts");
        assert!(flows[0].message.contains("process.argv"));
        assert!(flows[0].message.contains("execSync"));
        assert!(flows[0].message.contains("lib.ts"));
    }

    #[test]
    fn resolves_transitive_chains_across_files() {
        let lib = unit(vec![
            function("run", &["cmd"], vec![call("execSync", vec![ident("cmd")])]),
            function("launch", &["x"], vec![call("run", vec![ident("x")])]),
        ]);
        let main = unit(vec![call(
            "launch",
            vec![AstNode::new(NodeKind::MemberAccess, span(), "process.argv[2]", vec![])],
        )]);

        let flows = CrossFileTaint::new(config())
            .find_flows(&[("lib.ts", &lib), ("main.ts", &main)]);
        assert_eq!(flows.len(), 1);
        assert!(flows[0].message.contains("through call to `launch`"));
    }

    #[test]
    fn tainted_returns_propagate_into_sinks() {
        // source.ts: function readInput() { return process.argv[2] }
        let source_file = unit(vec![function(
            "readInput",
            &[],
            vec![AstNode::new(
                NodeKind::Other("return_statement".into()),
                span(),
                "return process.argv[2]",
                vec![AstNode::new(NodeKind::MemberAccess, span(), "process.argv[2]", vec![])],
            )],
        )]);
        // lib.ts: function run(cmd) { execSync(cmd) }
        let lib = unit(vec![function("run", &["cmd"], vec![call("execSync", vec![ident("cmd")])])]);
        // main.ts: data = readInput(); run(data)
        let main = unit(vec![
            AstNode::new(
                NodeKind::VariableDecl,
                span(),
                "data = readInput()",
                vec![ident("data"), call("readInput", vec![])],
            ),
            call("run", vec![ident("data")]),
        ]);

        let flows = CrossFileTaint::new(config()).find_flows(&[
            ("source.ts", &source_file),
            ("lib.ts", &lib),
            ("main.ts", &main),
        ]);
        assert_eq!(flows.len(), 1);
        assert!(flows[0].message.contains("readInput()"));
    }

    #[test]
    fn clean_calls_produce_nothing() {
        let lib = unit(vec![function("run", &["cmd"], vec![call("execSync", vec![ident("cmd")])])]);
        let main = unit(vec![call(
            "run",
            vec![AstNode::new(NodeKind::StringLiteral, span(), "\"ls\"", vec![])],
        )]);
        let flows =
            CrossFileTaint::new(config()).find_flows(&[("lib.ts", &lib), ("main.ts", &main)]);
        assert!(flows.is_empty());
    }

    fn config_with_sanitizer() -> TaintConfig {
        config().with_sanitizer("sanitize")
    }

    #[test]
    fn sanitized_argument_to_a_summarized_call_does_not_flow() {
        // lib.ts: function run(cmd) { execSync(cmd) }
        let lib = unit(vec![function("run", &["cmd"], vec![call("execSync", vec![ident("cmd")])])]);
        // main.ts: input = process.argv[2]; run(sanitize(input))
        let main = unit(vec![
            AstNode::new(
                NodeKind::VariableDecl,
                span(),
                "input = process.argv[2]",
                vec![ident("input"), AstNode::new(NodeKind::MemberAccess, span(), "process.argv[2]", vec![])],
            ),
            call("run", vec![call("sanitize", vec![ident("input")])]),
        ]);

        let flows = CrossFileTaint::new(config_with_sanitizer())
            .find_flows(&[("lib.ts", &lib), ("main.ts", &main)]);
        assert!(flows.is_empty());
    }

    #[test]
    fn sanitized_source_directly_at_a_summarized_call_does_not_flow() {
        let lib = unit(vec![function("run", &["cmd"], vec![call("execSync", vec![ident("cmd")])])]);
        let main = unit(vec![call(
            "run",
            vec![call(
                "sanitize",
                vec![AstNode::new(NodeKind::MemberAccess, span(), "process.argv[2]", vec![])],
            )],
        )]);

        let flows = CrossFileTaint::new(config_with_sanitizer())
            .find_flows(&[("lib.ts", &lib), ("main.ts", &main)]);
        assert!(flows.is_empty());
    }

    #[test]
    fn unsanitized_cross_file_flow_is_still_detected() {
        let lib = unit(vec![function("run", &["cmd"], vec![call("execSync", vec![ident("cmd")])])]);
        let main = unit(vec![call(
            "run",
            vec![AstNode::new(NodeKind::MemberAccess, span(), "process.argv[2]", vec![])],
        )]);

        let flows = CrossFileTaint::new(config_with_sanitizer())
            .find_flows(&[("lib.ts", &lib), ("main.ts", &main)]);
        assert_eq!(flows.len(), 1);
    }
}
