//! Application wiring for the yunq CLI: composes the default parsers,
//! rulesets and profile into an `AnalyzerService` and exposes the scan
//! use-case plus the output DTOs (serialization lives here, at the edge —
//! never on domain types).

use std::path::Path;

use yunq_infra_memory::{InMemoryIssueStorage, InMemoryMetricsTracker};
use yunq_parser_rust::RustParser;
use yunq_parser_typescript::TypeScriptParser;
use yunq_rules_engine::{
    AnalysisReport, AnalyzerService, IssueStorage, MetricsTracker, QualityProfile, Rule,
};

pub mod output;

/// Builds the default analyzer: both parsers, every shipped rule, and a
/// profile activating each rule at its default severity.
pub fn default_service<S, M>(storage: S, metrics: M) -> AnalyzerService<S, M>
where
    S: IssueStorage,
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
        .register_parser(Box::new(RustParser::new()));
    for rule in rules {
        service = service.register_rule(rule);
    }
    service
}

/// Scans a directory (or single file) with the default analyzer.
pub async fn scan(path: &Path) -> anyhow::Result<AnalysisReport> {
    let sources = yunq_infra_fs::collect_sources(path)?;
    let service = default_service(InMemoryIssueStorage::new(), InMemoryMetricsTracker::new());
    Ok(service.analyze_files(&sources).await?)
}
