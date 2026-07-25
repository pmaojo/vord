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
//! Name resolution: a call site's callee is resolved through
//! [`crate::module_graph`], a real import/export module edge graph built
//! from ES module `import` statements — a call to a name explicitly
//! imported from `'./lib'` resolves to that specific file's function, never
//! to a same-named function in an unrelated module. Functions are keyed by
//! `(file, name)`, not by name alone, so two unrelated files that happen to
//! define a same-named function no longer get conflated. A same-file call to
//! a locally declared function resolves directly, with no import needed.
//! Files with no recognized `import` syntax at all (synthetic ASTs in tests,
//! or languages/constructs this module doesn't parse imports for) fall back
//! to the previous project-wide by-name lookup (first definition wins) — a
//! deliberate, narrower fallback rather than a silent behavior change for
//! callers outside the ES-module family.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use yunq_ast::{AstNode, NodeKind, Span};

use crate::module_graph::{self, FunctionKey, ModuleImports};
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

/// Read-only context threaded through resolution: which file a node belongs
/// to, plus the graph data needed to turn a callee name into a
/// [`FunctionKey`].
struct ResolveCtx<'a> {
    file: &'a str,
    imports: &'a HashMap<String, ModuleImports>,
    local_functions: &'a HashSet<FunctionKey>,
    global_fallback: &'a HashMap<String, FunctionKey>,
}

pub struct CrossFileTaint {
    config: TaintConfig,
}

impl CrossFileTaint {
    pub fn new(config: TaintConfig) -> Self {
        Self { config }
    }

    pub fn find_flows(&self, files: &[(&str, &AstNode)]) -> Vec<CrossFileFlow> {
        let all_paths: Vec<&str> = files.iter().map(|(path, _)| *path).collect();
        let imports: HashMap<String, ModuleImports> = files
            .iter()
            .map(|(path, ast)| (path.to_string(), module_graph::collect_imports(path, ast, &all_paths)))
            .collect();

        let functions = collect_functions(files);
        let local_functions: HashSet<FunctionKey> =
            functions.iter().map(|f| (f.file.clone(), f.name.clone())).collect();
        let global_fallback = build_global_fallback(&functions);

        let mut summaries: HashMap<FunctionKey, Summary> =
            functions.iter().map(|f| ((f.file.clone(), f.name.clone()), Summary::default())).collect();

        // Phase 1: summaries to a global fixpoint (bounded).
        for _ in 0..10 {
            let mut changed = false;
            for function in &functions {
                let ctx = ResolveCtx {
                    file: &function.file,
                    imports: &imports,
                    local_functions: &local_functions,
                    global_fallback: &global_fallback,
                };
                let (summary, _) = self.analyze(function.body, &function.params, &ctx, &summaries);
                let key = (function.file.clone(), function.name.clone());
                if summaries.get(&key) != Some(&summary) {
                    summaries.insert(key, summary);
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
            let ctx = ResolveCtx {
                file: path,
                imports: &imports,
                local_functions: &local_functions,
                global_fallback: &global_fallback,
            };
            let (_, emissions) = self.analyze(ast, &[], &ctx, &summaries);
            flows.extend(emissions);
        }
        flows.sort_by(|a, b| {
            (&a.file, a.span.start_line, &a.message).cmp(&(&b.file, b.span.start_line, &b.message))
        });
        flows.dedup();
        flows
    }

    /// Resolves a callee name seen at a call site in `ctx.file` to the
    /// function it actually refers to: an explicit import binding first, a
    /// same-file local declaration second, and — only for files with no
    /// recognized `import` syntax at all — the legacy project-wide by-name
    /// lookup as a last resort (see module docs).
    fn resolve_callee(&self, name: &str, ctx: &ResolveCtx) -> Option<FunctionKey> {
        if let Some(target) = ctx.imports.get(ctx.file).and_then(|i| i.bindings.get(name)) {
            return Some(target.clone());
        }
        let local = (ctx.file.to_string(), name.to_string());
        if ctx.local_functions.contains(&local) {
            return Some(local);
        }
        let has_imports = ctx.imports.get(ctx.file).is_some_and(|i| i.has_import_statements);
        if has_imports {
            return None;
        }
        ctx.global_fallback.get(name).cloned()
    }

    /// Propagates taint through variable bindings (`VariableDecl`/
    /// `Assignment`) to a local fixpoint: repeatedly re-scans until no
    /// binding's known origins grow, so a chain like `a = b; c = a;`
    /// resolves regardless of declaration order.
    fn propagate_bindings(
        &self,
        body: &AstNode,
        ctx: &ResolveCtx,
        tainted: &mut HashMap<String, Origins>,
        summaries: &HashMap<FunctionKey, Summary>,
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
                    origins.extend(self.origins_of(value, ctx, tainted, summaries));
                }
                if origins.is_empty() {
                    continue;
                }

                let target_text = target.text();
                if let Some(entry) = tainted.get_mut(target_text) {
                    let before = entry.len();
                    entry.extend(origins);
                    changed |= entry.len() != before;
                } else {
                    tainted.insert(target_text.to_string(), origins);
                    changed = true;
                }
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
        ctx: &ResolveCtx,
        file: &str,
        tainted: &HashMap<String, Origins>,
        summaries: &HashMap<FunctionKey, Summary>,
        summary: &mut Summary,
    ) {
        if !self.is_sink(callee) {
            return;
        }
        let name = callee_name(callee);
        for arg in &call.children()[1..] {
            for origin in self.origins_of(arg, ctx, tainted, summaries) {
                if let Origin::Param(i) = origin {
                    summary.param_to_sink.entry(i).or_insert_with(|| format!("`{name}` ({file})"));
                }
            }
        }
    }

    /// Summarized call: its dangerous parameters are extended sinks — a
    /// param-origin extends this region's own summary, a source-origin
    /// emits a finding directly (the flow is complete here). `name` is the
    /// literal callee text at the call site (used in messages); resolution
    /// to the actual summarized function goes through `ctx`.
    #[allow(clippy::too_many_arguments)]
    fn record_summarized_call(
        &self,
        call: &AstNode,
        name: &str,
        ctx: &ResolveCtx,
        file: &str,
        tainted: &HashMap<String, Origins>,
        summaries: &HashMap<FunctionKey, Summary>,
        summary: &mut Summary,
        emissions: &mut Vec<CrossFileFlow>,
    ) {
        let Some(key) = self.resolve_callee(name, ctx) else { return };
        let Some(callee_summary) = summaries.get(&key) else { return };
        for (arg_index, arg) in call.children()[1..].iter().enumerate() {
            let Some(sink) = callee_summary.param_to_sink.get(&arg_index) else { continue };
            for origin in self.origins_of(arg, ctx, tainted, summaries) {
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
    #[allow(clippy::too_many_arguments)]
    fn analyze_calls(
        &self,
        body: &AstNode,
        ctx: &ResolveCtx,
        file: &str,
        tainted: &HashMap<String, Origins>,
        summaries: &HashMap<FunctionKey, Summary>,
        summary: &mut Summary,
        emissions: &mut Vec<CrossFileFlow>,
    ) {
        for call in body.descendants().filter(|n| *n.kind() == NodeKind::Call) {
            let Some(callee) = call.first_child() else { continue };
            let name = callee_name(callee);
            self.record_direct_sink(call, callee, ctx, file, tainted, summaries, summary);
            self.record_summarized_call(call, &name, ctx, file, tainted, summaries, summary, emissions);
        }
    }

    /// Returns: which taints escape through the return value.
    fn analyze_returns(
        &self,
        body: &AstNode,
        ctx: &ResolveCtx,
        tainted: &HashMap<String, Origins>,
        summaries: &HashMap<FunctionKey, Summary>,
        summary: &mut Summary,
    ) {
        for ret in body.descendants().filter(|n| match n.kind() {
            NodeKind::Other(kind) => kind.starts_with("return"),
            _ => false,
        }) {
            for origin in self.origins_of(ret, ctx, tainted, summaries) {
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
        ctx: &ResolveCtx,
        summaries: &HashMap<FunctionKey, Summary>,
    ) -> (Summary, Vec<CrossFileFlow>) {
        let mut tainted: HashMap<String, Origins> = params
            .iter()
            .enumerate()
            .map(|(i, name)| (name.clone(), BTreeSet::from([Origin::Param(i)])))
            .collect();
        self.propagate_bindings(body, ctx, &mut tainted, summaries);

        let mut summary = Summary::default();
        let mut emissions = Vec::new();
        self.analyze_calls(body, ctx, ctx.file, &tainted, summaries, &mut summary, &mut emissions);
        self.analyze_returns(body, ctx, &tainted, summaries, &mut summary);

        (summary, emissions)
    }

    /// All taint origins reaching a `Call` node: does it return
    /// source-tainted data itself, or forward one of its own tainted
    /// arguments through to its return value (per its summary)?
    fn call_origins(
        &self,
        node: &AstNode,
        ctx: &ResolveCtx,
        tainted: &HashMap<String, Origins>,
        summaries: &HashMap<FunctionKey, Summary>,
    ) -> Origins {
        let mut origins = Origins::new();
        let Some(callee) = node.first_child() else { return origins };
        let name = callee_name(callee);
        let Some(key) = self.resolve_callee(&name, ctx) else { return origins };
        let Some(summary) = summaries.get(&key) else { return origins };
        if summary.returns_source {
            origins.insert(Origin::Source(format!("{name}()")));
        }
        for (i, arg) in node.children()[1..].iter().enumerate() {
            if summary.param_to_return.contains(&i) {
                origins.extend(self.origins_of(arg, ctx, tainted, summaries));
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
        ctx: &ResolveCtx,
        tainted: &HashMap<String, Origins>,
        summaries: &HashMap<FunctionKey, Summary>,
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
        self.collect_unsanitized_origins(expr, ctx, tainted, summaries, &mut origins);
        origins
    }

    /// Visits `node` and its descendants for identifier/call origins,
    /// skipping any subtree rooted at a sanitizer call.
    fn collect_unsanitized_origins(
        &self,
        node: &AstNode,
        ctx: &ResolveCtx,
        tainted: &HashMap<String, Origins>,
        summaries: &HashMap<FunctionKey, Summary>,
        origins: &mut Origins,
    ) {
        match node.kind() {
            NodeKind::Identifier => {
                if let Some(known) = tainted.get(node.text()) {
                    origins.extend(known.iter().cloned());
                }
            }
            NodeKind::Call => origins.extend(self.call_origins(node, ctx, tainted, summaries)),
            _ => {}
        }
        for child in node.children() {
            if self.is_sanitized(child) {
                continue;
            }
            self.collect_unsanitized_origins(child, ctx, tainted, summaries, origins);
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
    let mut seen: BTreeSet<FunctionKey> = BTreeSet::new();
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
            // First declaration of a given name wins within its own file —
            // functions are now keyed per-file, so a same-named function in
            // a different file is a distinct entry, not a collision.
            if !seen.insert((path.to_string(), name.clone())) {
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

/// The pre-module-graph resolution behavior: first function definition wins
/// project-wide, by name alone. Kept only as a fallback for files with no
/// recognized `import` syntax (see module docs) — real ES-module files never
/// consult this.
fn build_global_fallback(functions: &[FunctionInfo]) -> HashMap<String, FunctionKey> {
    let mut map = HashMap::new();
    for function in functions {
        map.entry(function.name.clone())
            .or_insert_with(|| (function.file.clone(), function.name.clone()));
    }
    map
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

    // --- Real import/export module graph (parsed TypeScript) ---

    fn parse_ts(path: &'static str, code: &str) -> (yunq_ast::SourceFile, AstNode) {
        use yunq_ast::{LanguageIdentifier, SourceFile};
        use yunq_rules_engine::AstParser;
        let file = SourceFile::new(path, code, LanguageIdentifier::typescript()).unwrap();
        let ast = yunq_parser_typescript::TypeScriptParser::new().parse(&file).unwrap();
        (file, ast)
    }

    #[test]
    fn same_named_function_in_an_unimported_file_is_not_conflated() {
        // Two files each define a `run` function under the same name. Only
        // `safe.ts`'s `run` is ever imported and called — `danger.ts`'s
        // same-named sink function must play no part in resolving that
        // call. Before the module graph, project-wide by-name resolution
        // risked exactly this conflation.
        let danger = parse_ts("danger.ts", "export function run(cmd) {\n  execSync(cmd);\n}\n");
        let safe = parse_ts("safe.ts", "export function run(cmd) {\n  console.log(cmd);\n}\n");
        let main = parse_ts(
            "main.ts",
            "import { run } from './safe';\nconst input = process.argv[2];\nrun(input);\n",
        );

        let files: Vec<(&str, &AstNode)> =
            vec![(danger.0.path(), &danger.1), (safe.0.path(), &safe.1), (main.0.path(), &main.1)];
        let flows = CrossFileTaint::new(config()).find_flows(&files);
        assert!(flows.is_empty(), "safe.ts's run() must not be conflated with danger.ts's: {flows:?}");
    }

    #[test]
    fn imported_function_resolves_to_the_correct_file_even_with_a_same_named_decoy() {
        // Mirror of the above with the import pointed at the dangerous file
        // instead — proves the graph resolves to the *specific* imported
        // file, not just "avoids the wrong one by luck".
        let danger = parse_ts("danger.ts", "export function run(cmd) {\n  execSync(cmd);\n}\n");
        let safe = parse_ts("safe.ts", "export function run(cmd) {\n  console.log(cmd);\n}\n");
        let main = parse_ts(
            "main.ts",
            "import { run } from './danger';\nconst input = process.argv[2];\nrun(input);\n",
        );

        let files: Vec<(&str, &AstNode)> =
            vec![(danger.0.path(), &danger.1), (safe.0.path(), &safe.1), (main.0.path(), &main.1)];
        let flows = CrossFileTaint::new(config()).find_flows(&files);
        assert_eq!(flows.len(), 1);
        assert!(flows[0].message.contains("danger.ts"));
    }

    #[test]
    fn aliased_named_import_resolves_through_its_original_export_name() {
        let lib = parse_ts("lib.ts", "export function run(cmd) {\n  execSync(cmd);\n}\n");
        let main = parse_ts(
            "main.ts",
            "import { run as execute } from './lib';\nconst input = process.argv[2];\nexecute(input);\n",
        );

        let files: Vec<(&str, &AstNode)> = vec![(lib.0.path(), &lib.1), (main.0.path(), &main.1)];
        let flows = CrossFileTaint::new(config()).find_flows(&files);
        assert_eq!(flows.len(), 1);
        assert!(flows[0].message.contains("through call to `execute`"));
    }

    #[test]
    fn default_import_resolves_by_the_target_functions_own_declared_name() {
        let lib = parse_ts("lib.ts", "export default function run(cmd) {\n  execSync(cmd);\n}\n");
        let main = parse_ts(
            "main.ts",
            "import run from './lib';\nconst input = process.argv[2];\nrun(input);\n",
        );

        let files: Vec<(&str, &AstNode)> = vec![(lib.0.path(), &lib.1), (main.0.path(), &main.1)];
        let flows = CrossFileTaint::new(config()).find_flows(&files);
        assert_eq!(flows.len(), 1);
    }

    #[test]
    fn relative_import_resolves_across_subdirectories() {
        let lib = parse_ts("src/lib/util.ts", "export function run(cmd) {\n  execSync(cmd);\n}\n");
        let main = parse_ts(
            "src/main.ts",
            "import { run } from './lib/util';\nconst input = process.argv[2];\nrun(input);\n",
        );

        let files: Vec<(&str, &AstNode)> = vec![(lib.0.path(), &lib.1), (main.0.path(), &main.1)];
        let flows = CrossFileTaint::new(config()).find_flows(&files);
        assert_eq!(flows.len(), 1);
        assert!(flows[0].message.contains("src/lib/util.ts"));
    }

    #[test]
    fn unimported_same_file_helper_still_resolves_locally() {
        // No import needed for a same-file call — the local-function branch
        // of resolution must still fire for real parsed files, not just the
        // legacy no-imports fallback.
        let lib = parse_ts(
            "lib.ts",
            "import cp from 'child_process';\nexport function run(cmd) {\n  cp.execSync(cmd);\n}\nexport function launch(x) {\n  run(x);\n}\n",
        );
        let main = parse_ts(
            "main.ts",
            "import { launch } from './lib';\nconst input = process.argv[2];\nlaunch(input);\n",
        );

        let files: Vec<(&str, &AstNode)> = vec![(lib.0.path(), &lib.1), (main.0.path(), &main.1)];
        let flows = CrossFileTaint::new(config()).find_flows(&files);
        assert_eq!(flows.len(), 1);
        assert!(flows[0].message.contains("through call to `launch`"));
    }
}
