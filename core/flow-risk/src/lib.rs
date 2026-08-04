//! Flow-level "is this sequence actually tested" detection — one level up
//! from `vord-crap`'s per-function risk score. Two independent sources of
//! findings, both expressed the same way (an ordered chain of functions,
//! each with its own line-coverage percentage):
//!
//! - [`detect_untested_sequences`]: auto-detected, same-file call chains
//!   (from `vord_flow_graph::CallGraph`) where an exercised entry point
//!   reaches a downstream function that line coverage shows was never
//!   executed at all — the case a per-function view like CRAP can't
//!   surface, because it never looks past one function's own span.
//! - [`evaluate_registered_flow`]: a human- or agent-declared sequence
//!   (`[[flows]]` in `vord.toml`, evaluated by `bin/cli`) for the cases
//!   static call-graph inference cannot reach at all — cross-file,
//!   cross-language, or dispatched through a router/queue/cron rather than
//!   a direct call.
//!
//! Coverage is read through [`vord_crap::coverage_in_span`] throughout, so
//! both sources inherit its fail-open posture: a span with no instrumented
//! line at all is `None` ("no evidence"), never treated as 0%-covered
//! ("confirmed untested"). A flow finding only ever reports a *confirmed*
//! gap — an instrumented span that really did record zero hits.

use std::collections::{BTreeMap, HashSet, VecDeque};

use vord_ast::Span;
use vord_flow_graph::CallGraph;

/// One function's place in a reported flow: its name, span, and coverage
/// (`None` when no coverage data touches this span at all).
#[derive(Clone, Debug, PartialEq)]
pub struct FlowStep {
    pub function: String,
    pub span: Span,
    pub coverage_percent: Option<f64>,
}

/// One auto-detected untested sequence: `steps[0]` is the exercised entry
/// point, `steps.last()` is the confirmed-unexecuted downstream function it
/// reaches (directly or transitively) — everything in between is the path
/// between them, in call order.
#[derive(Clone, Debug, PartialEq)]
pub struct FlowFinding {
    pub path: String,
    pub steps: Vec<FlowStep>,
}

impl FlowFinding {
    pub fn entry(&self) -> &FlowStep {
        self.steps.first().expect("a FlowFinding always has >= 2 steps")
    }

    pub fn weak_link(&self) -> &FlowStep {
        self.steps.last().expect("a FlowFinding always has >= 2 steps")
    }
}

/// For every root (same-file, no-incoming-edge candidate entry point) in
/// `graph` that coverage shows was actually exercised, finds the shortest
/// call chain from it to a function whose own span is confirmed
/// unexecuted (`coverage_in_span == Some(0.0)`) — reported as one
/// [`FlowFinding`] per root, capped at `max_depth` hops so a large file
/// can't produce an unbounded search.
///
/// A root with no coverage data at all is skipped (nothing to claim it's
/// "exercised" from), and so is one already at 0% itself — that is an
/// ordinary CRAP finding, not a sequence spanning more than one function.
pub fn detect_untested_sequences(
    path: &str,
    graph: &CallGraph,
    lines: &BTreeMap<u32, usize>,
    max_depth: usize,
) -> Vec<FlowFinding> {
    let mut findings = Vec::new();
    for root in graph.roots() {
        let root_span = graph.functions[root].span;
        let Some(root_coverage) = vord_crap::coverage_in_span(lines, root_span) else {
            continue;
        };
        if root_coverage <= 0.0 {
            continue;
        }
        let Some(chain) = shortest_confirmed_untested_chain(graph, root, lines, max_depth) else {
            continue;
        };
        let steps = chain
            .into_iter()
            .map(|index| {
                let function = &graph.functions[index];
                FlowStep {
                    function: function.name.clone(),
                    span: function.span,
                    coverage_percent: vord_crap::coverage_in_span(lines, function.span),
                }
            })
            .collect();
        findings.push(FlowFinding {
            path: path.to_string(),
            steps,
        });
    }
    findings
}

/// Breadth-first, so the first confirmed-untested function found is
/// reachable in the fewest hops from `root` — the most legible chain to
/// report, and the cheapest to fix (shortest path to a passing test).
fn shortest_confirmed_untested_chain(
    graph: &CallGraph,
    root: usize,
    lines: &BTreeMap<u32, usize>,
    max_depth: usize,
) -> Option<Vec<usize>> {
    let mut visited: HashSet<usize> = HashSet::from([root]);
    let mut queue: VecDeque<Vec<usize>> = VecDeque::from([vec![root]]);
    while let Some(chain) = queue.pop_front() {
        if chain.len() > max_depth {
            continue;
        }
        let last = *chain.last().expect("chain is never empty");
        for callee in graph.callees(last) {
            if !visited.insert(callee) {
                continue;
            }
            let mut next = chain.clone();
            next.push(callee);
            if vord_crap::coverage_in_span(lines, graph.functions[callee].span) == Some(0.0) {
                return Some(next);
            }
            queue.push_back(next);
        }
    }
    None
}

/// One declared step of a [`RegisteredFlow`]: `path` is repository-relative
/// (the same convention `Issue::file()` and ingested coverage reports
/// already use), `function` is that function's declared name in `path`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegisteredStep {
    pub path: String,
    pub function: String,
}

/// A named, explicitly ordered sequence a human or agent has registered for
/// vord to track — the escape hatch for a flow [`detect_untested_sequences`]
/// cannot infer on its own.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegisteredFlow {
    pub name: String,
    pub steps: Vec<RegisteredStep>,
}

/// One evaluated step of a [`RegisteredFlow`].
#[derive(Clone, Debug, PartialEq)]
pub enum RegisteredStepResult {
    /// `function` was not found in `path` at all — most likely the flow
    /// drifted from a rename/move since it was registered. Always worth
    /// surfacing: this is a config-drift problem, not a coverage judgement.
    Missing { path: String, function: String },
    /// Found; `coverage_percent` is `None` when no ingested coverage report
    /// covers this span at all (fail-open: absence of data is not evidence
    /// of the step being untested).
    Found {
        path: String,
        function: String,
        span: Span,
        coverage_percent: Option<f64>,
    },
}

/// One registered flow's evaluated steps, in the declared order.
#[derive(Clone, Debug, PartialEq)]
pub struct RegisteredFlowResult {
    pub name: String,
    pub steps: Vec<RegisteredStepResult>,
}

impl RegisteredFlowResult {
    /// The first step that is either missing or confirmed unexecuted
    /// (`coverage_percent == Some(0.0)`) — the flow's weakest *verified*
    /// link. A step with no coverage data at all is never reported here:
    /// absent evidence is not evidence of being untested, the same
    /// fail-open posture [`vord_crap::coverage_in_span`] already takes.
    pub fn first_confirmed_gap(&self) -> Option<&RegisteredStepResult> {
        self.steps.iter().find(|step| match step {
            RegisteredStepResult::Missing { .. } => true,
            RegisteredStepResult::Found {
                coverage_percent, ..
            } => *coverage_percent == Some(0.0),
        })
    }
}

/// Evaluates one [`RegisteredFlow`] against a project-wide function index
/// (`(path, function name) -> span`, built by parsing each step's file) and
/// per-file coverage lines (`path -> instrumented-line -> hit-count`, from
/// an ingested coverage report).
pub fn evaluate_registered_flow(
    flow: &RegisteredFlow,
    function_index: &BTreeMap<(String, String), Span>,
    file_lines: &BTreeMap<String, BTreeMap<u32, usize>>,
) -> RegisteredFlowResult {
    let steps = flow
        .steps
        .iter()
        .map(|step| {
            let key = (step.path.clone(), step.function.clone());
            match function_index.get(&key) {
                None => RegisteredStepResult::Missing {
                    path: step.path.clone(),
                    function: step.function.clone(),
                },
                Some(&span) => {
                    let coverage_percent = file_lines
                        .get(&step.path)
                        .and_then(|lines| vord_crap::coverage_in_span(lines, span));
                    RegisteredStepResult::Found {
                        path: step.path.clone(),
                        function: step.function.clone(),
                        span,
                        coverage_percent,
                    }
                }
            }
        })
        .collect();
    RegisteredFlowResult {
        name: flow.name.clone(),
        steps,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vord_flow_graph::{CallEdge, FunctionSymbol};

    fn graph(functions: &[(&str, Span)], edges: &[(usize, usize)]) -> CallGraph {
        CallGraph {
            functions: functions
                .iter()
                .map(|(name, span)| FunctionSymbol {
                    name: name.to_string(),
                    span: *span,
                })
                .collect(),
            edges: edges
                .iter()
                .map(|&(caller, callee)| CallEdge { caller, callee })
                .collect(),
        }
    }

    #[test]
    fn finds_the_shortest_chain_from_an_exercised_root_to_a_confirmed_gap() {
        // a() [covered] -> b() [covered] -> c() [0% covered]
        let g = graph(
            &[
                ("a", Span::new(1, 1, 1, 5)),
                ("b", Span::new(2, 1, 2, 5)),
                ("c", Span::new(3, 1, 3, 5)),
            ],
            &[(0, 1), (1, 2)],
        );
        let mut lines = BTreeMap::new();
        lines.insert(1, 3);
        lines.insert(2, 1);
        lines.insert(3, 0);

        let findings = detect_untested_sequences("a.rs", &g, &lines, 4);

        assert_eq!(findings.len(), 1);
        let finding = &findings[0];
        assert_eq!(finding.path, "a.rs");
        assert_eq!(finding.entry().function, "a");
        assert_eq!(finding.weak_link().function, "c");
        assert_eq!(finding.weak_link().coverage_percent, Some(0.0));
    }

    #[test]
    fn root_with_no_coverage_data_produces_no_finding() {
        let g = graph(&[("a", Span::new(1, 1, 1, 5)), ("b", Span::new(2, 1, 2, 5))], &[(0, 1)]);
        let mut lines = BTreeMap::new();
        lines.insert(2, 0); // only b is instrumented, a has no data at all
        assert!(detect_untested_sequences("a.rs", &g, &lines, 4).is_empty());
    }

    #[test]
    fn already_uncovered_root_is_not_reported_as_a_multi_step_sequence() {
        let g = graph(&[("a", Span::new(1, 1, 1, 5)), ("b", Span::new(2, 1, 2, 5))], &[(0, 1)]);
        let mut lines = BTreeMap::new();
        lines.insert(1, 0);
        lines.insert(2, 0);
        assert!(detect_untested_sequences("a.rs", &g, &lines, 4).is_empty());
    }

    #[test]
    fn fully_covered_chain_produces_no_finding() {
        let g = graph(&[("a", Span::new(1, 1, 1, 5)), ("b", Span::new(2, 1, 2, 5))], &[(0, 1)]);
        let mut lines = BTreeMap::new();
        lines.insert(1, 3);
        lines.insert(2, 1);
        assert!(detect_untested_sequences("a.rs", &g, &lines, 4).is_empty());
    }

    #[test]
    fn max_depth_bounds_the_search() {
        // a -> b -> c[0%], but max_depth=1 only lets the search reach b.
        let g = graph(
            &[
                ("a", Span::new(1, 1, 1, 5)),
                ("b", Span::new(2, 1, 2, 5)),
                ("c", Span::new(3, 1, 3, 5)),
            ],
            &[(0, 1), (1, 2)],
        );
        let mut lines = BTreeMap::new();
        lines.insert(1, 3);
        lines.insert(2, 1);
        lines.insert(3, 0);

        assert!(detect_untested_sequences("a.rs", &g, &lines, 1).is_empty());
    }

    #[test]
    fn registered_flow_reports_the_first_confirmed_gap() {
        let flow = RegisteredFlow {
            name: "checkout".to_string(),
            steps: vec![
                RegisteredStep {
                    path: "checkout.ts".to_string(),
                    function: "start".to_string(),
                },
                RegisteredStep {
                    path: "payment.ts".to_string(),
                    function: "charge".to_string(),
                },
            ],
        };
        let mut function_index = BTreeMap::new();
        function_index.insert(
            ("checkout.ts".to_string(), "start".to_string()),
            Span::new(1, 1, 1, 5),
        );
        function_index.insert(
            ("payment.ts".to_string(), "charge".to_string()),
            Span::new(1, 1, 1, 5),
        );
        let mut file_lines = BTreeMap::new();
        let mut checkout_lines = BTreeMap::new();
        checkout_lines.insert(1, 2);
        file_lines.insert("checkout.ts".to_string(), checkout_lines);
        let mut payment_lines = BTreeMap::new();
        payment_lines.insert(1, 0);
        file_lines.insert("payment.ts".to_string(), payment_lines);

        let result = evaluate_registered_flow(&flow, &function_index, &file_lines);

        let gap = result.first_confirmed_gap().expect("payment.ts:charge is 0% covered");
        assert!(matches!(
            gap,
            RegisteredStepResult::Found { function, coverage_percent: Some(p), .. }
                if function == "charge" && *p == 0.0
        ));
    }

    #[test]
    fn registered_flow_flags_a_missing_step() {
        let flow = RegisteredFlow {
            name: "checkout".to_string(),
            steps: vec![RegisteredStep {
                path: "checkout.ts".to_string(),
                function: "renamed_away".to_string(),
            }],
        };
        let result = evaluate_registered_flow(&flow, &BTreeMap::new(), &BTreeMap::new());

        assert!(matches!(
            result.first_confirmed_gap(),
            Some(RegisteredStepResult::Missing { function, .. }) if function == "renamed_away"
        ));
    }

    #[test]
    fn registered_flow_with_no_coverage_data_is_not_a_confirmed_gap() {
        let flow = RegisteredFlow {
            name: "checkout".to_string(),
            steps: vec![RegisteredStep {
                path: "checkout.ts".to_string(),
                function: "start".to_string(),
            }],
        };
        let mut function_index = BTreeMap::new();
        function_index.insert(
            ("checkout.ts".to_string(), "start".to_string()),
            Span::new(1, 1, 1, 5),
        );
        // No entry in file_lines at all: no coverage report touched this file.
        let result = evaluate_registered_flow(&flow, &function_index, &BTreeMap::new());

        assert!(result.first_confirmed_gap().is_none());
    }

    #[test]
    fn fully_tested_registered_flow_has_no_gap() {
        let flow = RegisteredFlow {
            name: "checkout".to_string(),
            steps: vec![RegisteredStep {
                path: "checkout.ts".to_string(),
                function: "start".to_string(),
            }],
        };
        let mut function_index = BTreeMap::new();
        function_index.insert(
            ("checkout.ts".to_string(), "start".to_string()),
            Span::new(1, 1, 1, 5),
        );
        let mut lines = BTreeMap::new();
        lines.insert(1, 5);
        let mut file_lines = BTreeMap::new();
        file_lines.insert("checkout.ts".to_string(), lines);

        let result = evaluate_registered_flow(&flow, &function_index, &file_lines);

        assert!(result.first_confirmed_gap().is_none());
    }
}
