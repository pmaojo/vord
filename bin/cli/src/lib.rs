//! Application wiring for the yunq CLI: composes the default parsers,
//! rulesets and profile into an `AnalyzerService` and exposes the scan
//! use-case plus the output DTOs (serialization lives here, at the edge —
//! never on domain types).

use std::path::Path;
use std::sync::Arc;

use yunq_infra_fs::FileAnalysisCache;
use yunq_infra_memory::{InMemoryIssueStorage, InMemoryMetricsTracker};
use yunq_parser_go::GoParser;
use yunq_parser_python::PythonParser;
use yunq_parser_rust::RustParser;
use yunq_parser_typescript::TypeScriptParser;
use yunq_rules_engine::{
    AnalysisReport, AnalyzerService, ComparisonOperator, Condition, HotspotStorage, IssueStorage,
    MetricKey, MetricsTracker, QualityGate, QualityProfile, Rule,
};

pub mod output;

/// Builds the default analyzer: both parsers, every shipped rule, and a
/// profile activating each rule at its default severity.
pub fn default_service<S, M>(storage: S, metrics: M) -> AnalyzerService<S, M>
where
    S: IssueStorage + HotspotStorage,
    M: MetricsTracker,
{
    let rules: Vec<Box<dyn Rule>> = yunq_rules_owasp::all_rules()
        .into_iter()
        .chain(yunq_rules_smells::all_rules())
        .collect();
    let profile = QualityProfile::from_activations(
        "yunq-default",
        rules.iter().map(|r| (r.id().clone(), r.default_severity())),
    );

    let mut service = AnalyzerService::new(profile, storage, metrics)
        .register_parser(Box::new(TypeScriptParser::new()))
        .register_parser(Box::new(RustParser::new()))
        .register_parser(Box::new(PythonParser::new()))
        .register_parser(Box::new(GoParser::new()));
    for rule in rules {
        service = service.register_rule(rule);
    }
    service
}

/// The built-in quality gate: no blocker or critical issues, and every file
/// must parse. Mirrors the Clean-as-You-Code default until per-project gates
/// arrive with the server-side quality model.
pub fn default_quality_gate() -> QualityGate {
    let metric = |raw: &str| MetricKey::new(raw).expect("valid metric key");
    QualityGate::new("yunq-default")
        .with_condition(Condition::new(metric("blocker_issues"), ComparisonOperator::GreaterThan, 0.0))
        .with_condition(Condition::new(metric("critical_issues"), ComparisonOperator::GreaterThan, 0.0))
        .with_condition(Condition::new(metric("parse_failures"), ComparisonOperator::GreaterThan, 0.0))
}

/// Scans a directory (or single file) with the default analyzer, without a
/// cache — fully deterministic, used by tests and one-off scans.
pub async fn scan(path: &Path) -> anyhow::Result<AnalysisReport> {
    scan_with_cache(path, None).await
}

/// Scans with an optional incremental cache; the caller decides persistence.
pub async fn scan_with_cache(
    path: &Path,
    cache: Option<Arc<FileAnalysisCache>>,
) -> anyhow::Result<AnalysisReport> {
    let sources = yunq_infra_fs::collect_sources(path)?;
    let mut service =
        default_service(InMemoryIssueStorage::new(), InMemoryMetricsTracker::new());
    if let Some(cache) = cache {
        service = service.with_cache(cache);
    }
    Ok(service.analyze_files(&sources).await?)
}
