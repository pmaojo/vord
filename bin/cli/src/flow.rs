//! Flow-level "is this sequence tested" detection (see `core/flow-graph`,
//! `core/flow-risk`). Two independent sources of findings, both gated on a
//! coverage report having been ingested — the same no-op-without-coverage
//! posture `crap::apply` already uses — and both folded into `report` as
//! ordinary [`ExternalIssue`]s via `add_external_issues`, the same
//! treatment SARIF import and CRAP already get: no new rendering plumbing,
//! the finding flows into text/JSON output, SARIF export and PR decoration
//! for free.
//!
//! - [`apply_auto_detected`]: same-file call chains, joined against the
//!   ingested coverage report.
//! - [`apply_registered`]: `[[flows]]` entries from `vord.toml`.
//!
//! Both re-parse only the specific files they need, independent of
//! `AnalyzerService`'s own cached parse pass — flow analysis is a pure
//! post-processing join, the same relationship `crap::apply` already has to
//! `AnalysisReport::function_complexities`.

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};

use vord_ast::{AstNode, LanguageIdentifier, SourceFile};
use vord_flow_risk::{FlowFinding, RegisteredFlow, RegisteredStep, RegisteredStepResult};
use vord_rules_engine::{
    AnalysisReport, AstParser, ExternalIssue, Issue, IssueType, RuleId, Severity,
};

const UNTESTED_SEQUENCE_RULE_ID: &str = "flow:untested-sequence";
const REGISTERED_GAP_RULE_ID: &str = "flow:registered-gap";
/// Bounds the auto-detection BFS: deep enough to catch a realistic
/// controller -> service -> repository chain, shallow enough that one file
/// can't blow up scan time.
const MAX_AUTO_DEPTH: usize = 4;

fn parser_registry() -> HashMap<LanguageIdentifier, Box<dyn AstParser>> {
    vord_cli::all_default_parsers()
        .into_iter()
        .map(|parser| (parser.language(), parser))
        .collect()
}

/// Reads and parses `relative` (repository-relative, matching how
/// coverage reports and `[[flows]]` steps both record paths) under `root`.
/// `None` covers every reason this can fail — unsupported/undetectable
/// language, missing file, non-UTF-8 content, parse failure — flow analysis
/// treats all of them the same way `crap::apply` treats missing coverage:
/// silently skip, never a scan-breaking error over a single file.
fn parse_relative(
    root: &Path,
    relative: &str,
    parsers: &HashMap<LanguageIdentifier, Box<dyn AstParser>>,
) -> Option<AstNode> {
    let language = Path::new(relative)
        .extension()
        .and_then(|ext| ext.to_str())
        .and_then(LanguageIdentifier::from_extension)?;
    let parser = parsers.get(&language)?;
    let content = std::fs::read_to_string(root.join(relative)).ok()?;
    let file = SourceFile::new(relative, content, language).ok()?;
    parser.parse(&file).ok()
}

/// Auto-detects untested call chains in every file the ingested coverage
/// report covers. No-op (returns an empty `Vec`, touches nothing on
/// `report`) when no coverage report was ingested.
pub fn apply_auto_detected(report: &mut AnalysisReport, root: &Path) -> Vec<FlowFinding> {
    let Some(coverage) = report.coverage_report() else {
        return Vec::new();
    };
    let parsers = parser_registry();
    let mut findings = Vec::new();
    for file_coverage in coverage.files() {
        let Some(ast) = parse_relative(root, file_coverage.path(), &parsers) else {
            continue;
        };
        let graph = vord_flow_graph::build(&ast);
        findings.extend(vord_flow_risk::detect_untested_sequences(
            file_coverage.path(),
            &graph,
            file_coverage.lines(),
            MAX_AUTO_DEPTH,
        ));
    }

    let issues: Vec<ExternalIssue> = findings
        .iter()
        .map(|finding| {
            let entry = finding.entry();
            let weak_link = finding.weak_link();
            let chain: Vec<&str> = finding.steps.iter().map(|s| s.function.as_str()).collect();
            let message = format!(
                "untested sequence: `{}` ({:.0}% covered) reaches `{}`, which is never executed \
                 (0% covered) — chain: {}",
                entry.function,
                entry.coverage_percent.unwrap_or(0.0),
                weak_link.function,
                chain.join(" -> "),
            );
            ExternalIssue::new(
                Issue::new(
                    rule_id(UNTESTED_SEQUENCE_RULE_ID),
                    Severity::Major,
                    message,
                    finding.path.clone(),
                    weak_link.span,
                ),
                IssueType::CodeSmell,
            )
        })
        .collect();
    report.add_external_issues(issues);
    findings
}

/// Evaluates every `[[flows]]` entry against the ingested coverage report,
/// re-parsing only the files its steps name. No-op when `flows` is empty.
pub fn apply_registered(
    report: &mut AnalysisReport,
    root: &Path,
    flows: &[vord_infra_fs::FlowConfig],
) {
    if flows.is_empty() {
        return;
    }
    let parsers = parser_registry();
    let file_lines: BTreeMap<String, BTreeMap<u32, usize>> = report
        .coverage_report()
        .map(|coverage| {
            coverage
                .files()
                .iter()
                .map(|f| (f.path().to_string(), f.lines().clone()))
                .collect()
        })
        .unwrap_or_default();

    let mut function_index: BTreeMap<(String, String), vord_ast::Span> = BTreeMap::new();
    let mut parsed_paths: std::collections::HashSet<&str> = std::collections::HashSet::new();
    for flow in flows {
        for step in &flow.steps {
            if !parsed_paths.insert(step.path.as_str()) {
                continue;
            }
            let Some(ast) = parse_relative(root, &step.path, &parsers) else {
                continue;
            };
            for function in vord_flow_graph::build(&ast).functions {
                function_index
                    .entry((step.path.clone(), function.name))
                    .or_insert(function.span);
            }
        }
    }

    let mut issues = Vec::new();
    for flow in flows {
        let registered = RegisteredFlow {
            name: flow.name.clone(),
            steps: flow
                .steps
                .iter()
                .map(|s| RegisteredStep {
                    path: s.path.clone(),
                    function: s.function.clone(),
                })
                .collect(),
        };
        let result =
            vord_flow_risk::evaluate_registered_flow(&registered, &function_index, &file_lines);
        let Some(gap) = result.first_confirmed_gap() else {
            continue;
        };
        let (path, message, span) = match gap {
            RegisteredStepResult::Missing { path, function } => (
                path.clone(),
                format!(
                    "registered flow `{}` step `{function}` not found in `{path}` — check for a \
                     rename or move since it was registered",
                    flow.name
                ),
                vord_ast::Span::new(1, 1, 1, 1),
            ),
            RegisteredStepResult::Found {
                path,
                function,
                span,
                ..
            } => (
                path.clone(),
                format!(
                    "registered flow `{}` step `{function}` ({path}) is never executed (0% \
                     covered) — this sequence is not verified end-to-end",
                    flow.name
                ),
                *span,
            ),
        };
        issues.push(ExternalIssue::new(
            Issue::new(
                rule_id(REGISTERED_GAP_RULE_ID),
                Severity::Major,
                message,
                path,
                span,
            ),
            IssueType::CodeSmell,
        ));
    }
    report.add_external_issues(issues);
}

fn rule_id(raw: &str) -> RuleId {
    RuleId::new(raw).expect("valid rule id")
}

/// Appends a `[[flows]]` entry to `root`'s `vord.toml`/`.vord.toml` — the
/// mechanism an AI agent (or a human) uses to register a sequence static
/// call-graph inference can't reach on its own. Appends raw TOML text
/// rather than deserializing/mutating/reserializing the whole document, so
/// every existing comment and the rest of the file survive untouched
/// byte-for-byte; the tradeoff is that `name`/`path`/`function` go through
/// Rust's `Debug` string escaping rather than a real TOML writer, which is
/// exact for the ordinary identifiers and repo-relative paths this is meant
/// for but not a general-purpose TOML serializer.
pub fn register(root: &Path, name: &str, steps: &[(String, String)]) -> anyhow::Result<()> {
    if steps.is_empty() {
        anyhow::bail!("a flow needs at least one --step path:function");
    }
    let config_path = existing_config_path(root);

    let mut block = String::new();
    block.push_str("\n[[flows]]\n");
    block.push_str(&format!("name = {}\n", toml_string(name)));
    for (step_path, function) in steps {
        block.push_str("\n  [[flows.steps]]\n");
        block.push_str(&format!("  path = {}\n", toml_string(step_path)));
        block.push_str(&format!("  function = {}\n", toml_string(function)));
    }

    use std::io::Write;
    std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&config_path)
        .and_then(|mut file| file.write_all(block.as_bytes()))?;

    // Fail loudly rather than leaving a silently-broken vord.toml behind:
    // reload and confirm the registered flow is actually there.
    let reloaded = vord_infra_fs::VordConfig::load_from_dir(root).ok_or_else(|| {
        anyhow::anyhow!(
            "{} no longer parses as valid TOML after the append",
            config_path.display()
        )
    })?;
    if !reloaded.flows.iter().any(|f| f.name == name) {
        anyhow::bail!(
            "wrote to {} but flow {name:?} isn't present after reloading it",
            config_path.display()
        );
    }
    Ok(())
}

/// `vord.toml` if it exists, else `.vord.toml` if it exists, else
/// `vord.toml` — the same precedence `VordConfig::load_from_dir` already
/// applies, so a registered flow always lands in the file that will
/// actually be read back.
fn existing_config_path(root: &Path) -> PathBuf {
    let vord_toml = root.join("vord.toml");
    if vord_toml.exists() {
        return vord_toml;
    }
    let dot_vord_toml = root.join(".vord.toml");
    if dot_vord_toml.exists() {
        return dot_vord_toml;
    }
    vord_toml
}

fn toml_string(s: &str) -> String {
    format!("{s:?}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use vord_rules_engine::{CoverageReport, FileCoverage, Metrics};

    fn write_file(dir: &std::path::Path, relative: &str, content: &str) {
        let path = dir.join(relative);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(path, content).unwrap();
    }

    fn temp_dir(name: &str) -> std::path::PathBuf {
        let dir =
            std::env::temp_dir().join(format!("vord-flow-test-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn auto_detected_is_a_noop_without_a_coverage_report() {
        let mut report = AnalysisReport::new(Vec::new(), Vec::new(), Metrics::new());
        let dir = temp_dir("noop");
        let findings = apply_auto_detected(&mut report, &dir);
        assert!(findings.is_empty());
        assert!(report.issues().is_empty());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn auto_detected_finds_an_untested_chain_from_source() {
        let dir = temp_dir("chain");
        write_file(
            &dir,
            "a.ts",
            "function entry() {\n  helper();\n}\n\nfunction helper() {\n  return 1;\n}\n",
        );
        let mut report = AnalysisReport::new(Vec::new(), Vec::new(), Metrics::new());
        let mut file_coverage = FileCoverage::new("a.ts");
        file_coverage.record_line(1, 3); // entry() executed
        file_coverage.record_line(5, 0); // helper() never executed
        report.set_coverage_report(CoverageReport::new(vec![file_coverage], 1, 2, 0, 0));

        let findings = apply_auto_detected(&mut report, &dir);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].entry().function, "entry");
        assert_eq!(findings[0].weak_link().function, "helper");
        assert_eq!(report.issues().len(), 1);
        assert_eq!(
            report.issues()[0].rule().as_str(),
            UNTESTED_SEQUENCE_RULE_ID
        );
        assert_eq!(report.issues()[0].severity(), Severity::Major);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn registered_is_a_noop_with_no_flows_configured() {
        let mut report = AnalysisReport::new(Vec::new(), Vec::new(), Metrics::new());
        let dir = temp_dir("registered-noop");
        apply_registered(&mut report, &dir, &[]);
        assert!(report.issues().is_empty());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn registered_flow_reports_a_missing_step() {
        let dir = temp_dir("registered-missing");
        write_file(&dir, "a.ts", "function present() {\n  return 1;\n}\n");
        let mut report = AnalysisReport::new(Vec::new(), Vec::new(), Metrics::new());
        let flows = vec![vord_infra_fs::FlowConfig {
            name: "example".to_string(),
            steps: vec![vord_infra_fs::FlowStepConfig {
                path: "a.ts".to_string(),
                function: "renamed_away".to_string(),
            }],
        }];

        apply_registered(&mut report, &dir, &flows);

        assert_eq!(report.issues().len(), 1);
        assert_eq!(report.issues()[0].rule().as_str(), REGISTERED_GAP_RULE_ID);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn registered_flow_with_no_coverage_data_reports_nothing() {
        let dir = temp_dir("registered-no-coverage");
        write_file(&dir, "a.ts", "function present() {\n  return 1;\n}\n");
        let mut report = AnalysisReport::new(Vec::new(), Vec::new(), Metrics::new());
        let flows = vec![vord_infra_fs::FlowConfig {
            name: "example".to_string(),
            steps: vec![vord_infra_fs::FlowStepConfig {
                path: "a.ts".to_string(),
                function: "present".to_string(),
            }],
        }];

        apply_registered(&mut report, &dir, &flows);

        assert!(report.issues().is_empty());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn register_appends_to_a_fresh_vord_toml() {
        let dir = temp_dir("register-fresh");
        register(
            &dir,
            "checkout-happy-path",
            &[
                ("src/checkout.ts".to_string(), "startCheckout".to_string()),
                ("src/payment.ts".to_string(), "chargeCard".to_string()),
            ],
        )
        .unwrap();

        let config = vord_infra_fs::VordConfig::load_from_dir(&dir).unwrap();
        assert_eq!(config.flows.len(), 1);
        assert_eq!(config.flows[0].name, "checkout-happy-path");
        assert_eq!(config.flows[0].steps.len(), 2);
        assert_eq!(config.flows[0].steps[0].function, "startCheckout");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn register_preserves_existing_vord_toml_content() {
        let dir = temp_dir("register-preserve");
        write_file(
            &dir,
            "vord.toml",
            "[project]\nkey = \"my-project\"\n\n[gate]\nmin_health_score = 90\n",
        );

        register(
            &dir,
            "checkout-happy-path",
            &[("src/checkout.ts".to_string(), "startCheckout".to_string())],
        )
        .unwrap();

        let raw = std::fs::read_to_string(dir.join("vord.toml")).unwrap();
        assert!(raw.contains("key = \"my-project\""));
        assert!(raw.contains("min_health_score = 90"));

        let config = vord_infra_fs::VordConfig::load_from_dir(&dir).unwrap();
        assert_eq!(config.project.key.as_deref(), Some("my-project"));
        assert_eq!(config.gate.min_health_score, Some(90));
        assert_eq!(config.flows.len(), 1);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn register_can_be_called_more_than_once() {
        let dir = temp_dir("register-twice");
        register(&dir, "flow-one", &[("a.ts".to_string(), "f1".to_string())]).unwrap();
        register(&dir, "flow-two", &[("b.ts".to_string(), "f2".to_string())]).unwrap();

        let config = vord_infra_fs::VordConfig::load_from_dir(&dir).unwrap();
        assert_eq!(config.flows.len(), 2);
        assert_eq!(config.flows[0].name, "flow-one");
        assert_eq!(config.flows[1].name, "flow-two");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn register_rejects_an_empty_step_list() {
        let dir = temp_dir("register-empty");
        let result = register(&dir, "empty-flow", &[]);
        assert!(result.is_err());
        std::fs::remove_dir_all(&dir).ok();
    }
}
