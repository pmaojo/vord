//! Composition root: queue worker. Instantiates the real adapters, injects
//! them into the pure `AnalyzerService`, and processes scan jobs from SQS.
//!
//! Env: `DATABASE_URL`, `YUNQ_QUEUE_URL`, `YUNQ_AWS_ENDPOINT_URL` (emulator).

use std::path::Path;

use yunq_infra_postgres::PgIssueStorage;
use yunq_infra_sqs::SqsJobConsumer;
use yunq_parser_rust::RustParser;
use yunq_parser_typescript::TypeScriptParser;
use yunq_rules_engine::{
    AnalyzerService, IssueStorage, MetricsTracker, QualityProfile, QueueError, Rule, ScanJob,
};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://yunq:yunq@localhost:5432/yunq".to_string());
    let queue_url = std::env::var("YUNQ_QUEUE_URL")
        .unwrap_or_else(|_| "http://localhost:4566/000000000000/yunq-scan-jobs".to_string());

    // 1. Instantiate adapters.
    let storage = PgIssueStorage::connect_lazy(&database_url)?;
    storage.migrate().await?;

    // 2. Inject them into the pure domain service.
    let service = default_service(storage.clone(), storage);

    // 3. Boot.
    let consumer = SqsJobConsumer::new(yunq_infra_sqs::sqs_client_from_env().await, queue_url);
    println!("yunq-worker consuming scan jobs");
    consumer.listen(|job| handle_job(&service, job)).await?;
    Ok(())
}

fn default_service<S, M>(storage: S, metrics: M) -> AnalyzerService<S, M>
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

async fn handle_job<S, M>(
    service: &AnalyzerService<S, M>,
    job: ScanJob,
) -> Result<(), QueueError>
where
    S: IssueStorage,
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
    Ok(())
}
