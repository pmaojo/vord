//! Composition root: queue worker. Instantiates the real adapters, injects
//! them into the pure `AnalyzerService`, and processes scan jobs claimed
//! from the `scan_jobs` Postgres table.
//!
//! Env: `DATABASE_URL`.

use std::path::Path;

use yunq_infra_postgres::{PgIssueStorage, PgJobConsumer};
use yunq_parser_go::GoParser;
use yunq_parser_java::JavaParser;
use yunq_parser_python::PythonParser;
use yunq_parser_rust::RustParser;
use yunq_parser_typescript::TypeScriptParser;
use yunq_rules_engine::{
    AnalyzerService, HotspotStorage, IssueStorage, MetricsTracker, QualityProfile, QueueError,
    Rule, ScanJob,
};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://yunq:yunq@localhost:5432/yunq".to_string());

    // 1. Instantiate adapters.
    let storage = PgIssueStorage::connect_lazy(&database_url)?;
    storage.migrate().await?;

    // 2. Inject them into the pure domain service. A separate handle to the
    // same pool persists the quality gate outcome once analysis finishes —
    // gate persistence is a Postgres-specific concern, not a core port, so it
    // stays outside the generic `AnalyzerService`.
    let consumer = PgJobConsumer::new(storage.pool().clone());
    let gate_storage = storage.clone();
    let service = default_service(storage.clone(), storage);

    // 3. Boot.
    println!("yunq-worker consuming scan jobs");
    consumer.listen(|job| handle_job(&service, &gate_storage, job)).await?;
    Ok(())
}

fn default_service<S, M>(storage: S, metrics: M) -> AnalyzerService<S, M>
where
    S: IssueStorage + HotspotStorage,
    M: MetricsTracker,
{
    let rules: Vec<Box<dyn Rule>> = yunq_rules_owasp::all_rules()
        .into_iter()
        .chain(yunq_rules_smells::all_rules())
        .chain(yunq_rules_iac::all_rules())
        .chain(yunq_rules_a11y::all_rules())
        .chain(yunq_rules_react::all_rules())
        .chain(yunq_rules_secrets::all_rules())
        .collect();
    let cross_rules = yunq_rules_owasp::all_cross_rules();
    let profile = QualityProfile::from_activations(
        "yunq-default",
        rules
            .iter()
            .map(|r| (r.id().clone(), r.default_severity()))
            .chain(cross_rules.iter().map(|r| (r.id().clone(), r.default_severity()))),
    );
    let mut service = AnalyzerService::new(profile, storage, metrics)
        .register_parser(Box::new(TypeScriptParser::new()))
        .register_parser(Box::new(RustParser::new()))
        .register_parser(Box::new(PythonParser::new()))
        .register_parser(Box::new(GoParser::new()))
        .register_parser(Box::new(JavaParser::new()));
    for rule in rules {
        service = service.register_rule(rule);
    }
    for rule in cross_rules {
        service = service.register_cross_rule(rule);
    }
    service
}

async fn handle_job<S, M>(
    service: &AnalyzerService<S, M>,
    gate_storage: &PgIssueStorage,
    job: ScanJob,
) -> Result<(), QueueError>
where
    S: IssueStorage + HotspotStorage,
    M: MetricsTracker,
{
    let sources = yunq_infra_fs::collect_sources(Path::new(job.path()))
        .map_err(|e| QueueError(e.to_string()))?;
    let report = service
        .analyze_files(&sources)
        .await
        .map_err(|e| QueueError(e.to_string()))?;
    println!(
        "scanned project {}: {} files, {} issues",
        job.project(),
        report.metrics().files_scanned(),
        report.metrics().issue_total()
    );

    // Quality gate: evaluate the project's assigned gate (or the built-in
    // default, if none was assigned) against this analysis' measures, and
    // persist the outcome so the status badge reflects a real result instead
    // of a hardcoded value. Best-effort: a failure here must not fail the
    // scan job itself (the issues/hotspots/metrics are already durable).
    const DEFAULT_BRANCH: &str = "main";
    match gate_storage.ensure_project(job.project()).await {
        Ok(project_id) => {
            let gate = gate_storage
                .gate_for_project(project_id)
                .await
                .unwrap_or_else(|_| yunq_rules_engine::default_gate());
            let evaluation = gate.evaluate(|key| report.measure(key));
            match gate_storage
                .record_analysis(
                    project_id,
                    DEFAULT_BRANCH,
                    report.metrics().lines_of_code() as i64,
                    report.metrics().issue_total() as i32,
                )
                .await
            {
                Ok(analysis_id) => {
                    if let Err(e) = gate_storage.save_gate_result(analysis_id, &evaluation).await {
                        eprintln!("warning: could not persist gate result: {e}");
                    } else {
                        println!("quality gate for {}: {}", job.project(), evaluation.status());
                    }
                }
                Err(e) => eprintln!("warning: could not record analysis: {e}"),
            }
        }
        Err(e) => eprintln!("warning: could not resolve project {}: {e}", job.project()),
    }

    Ok(())
}
