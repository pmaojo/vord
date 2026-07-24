//! Composition root: queue worker. Instantiates the real adapters, injects
//! them into the pure `AnalyzerService`, and processes scan jobs claimed
//! from the `scan_jobs` Postgres table.
//!
//! Env: `DATABASE_URL`, `YUNQ_DEFAULT_RETENTION_DAYS`,
//! `YUNQ_HOUSEKEEPING_INTERVAL_HOURS`.

use std::path::Path;
use std::time::Duration;

use yunq_infra_postgres::{PgIssueStorage, PgJobConsumer};
use yunq_parser_go::GoParser;
use yunq_parser_java::JavaParser;
use yunq_parser_python::PythonParser;
use yunq_parser_rust::RustParser;
use yunq_parser_typescript::TypeScriptParser;
use yunq_rules_engine::{
    AnalysisReport, AnalyzerService, HotspotStorage, IssueScope, IssueStorage, MeasureStorage,
    MetricsTracker, QueueError, Rule, ScanJob,
};

/// Every scan is recorded against this branch; matches the rest of the
/// gate/analysis persistence path (`persist_gate_result`,
/// `record_analysis`/`record_analysis_pending`), which has never taken a
/// real branch name from the job.
const DEFAULT_BRANCH: &str = "main";

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

    // 3. Boot. Housekeeping runs on its own timer alongside the job-consume
    // loop rather than blocking it — a purge is unrelated to, and much
    // rarer than, scan-job throughput.
    tokio::spawn(run_housekeeping_loop(gate_storage.clone()));
    println!("yunq-worker consuming scan jobs");
    consumer.listen(|job| handle_job(&service, &gate_storage, job)).await?;
    Ok(())
}

/// Periodically deletes analyses, issues and hotspots past each project's
/// effective retention (its own override, else
/// `YUNQ_DEFAULT_RETENTION_DAYS`). A project with neither set is left
/// untouched — retention is opt-in, not a silent default, since deletion
/// isn't reversible. Runs once at startup, then every
/// `YUNQ_HOUSEKEEPING_INTERVAL_HOURS` (default 24).
async fn run_housekeeping_loop(storage: PgIssueStorage) {
    let default_days = std::env::var("YUNQ_DEFAULT_RETENTION_DAYS")
        .ok()
        .and_then(|raw| raw.parse::<i32>().ok());
    let interval_hours: u64 = std::env::var("YUNQ_HOUSEKEEPING_INTERVAL_HOURS")
        .ok()
        .and_then(|raw| raw.parse().ok())
        .unwrap_or(24);
    let mut ticker = tokio::time::interval(Duration::from_secs(interval_hours * 3600));

    loop {
        ticker.tick().await;
        match storage.purge_expired(default_days).await {
            Ok(report)
                if report.analyses_deleted > 0
                    || report.issues_deleted > 0
                    || report.hotspots_deleted > 0 =>
            {
                println!(
                    "housekeeping: purged {} expired analyses, {} issues, {} hotspots",
                    report.analyses_deleted, report.issues_deleted, report.hotspots_deleted
                );
            }
            Ok(_) => {}
            Err(e) => eprintln!("warning: housekeeping purge failed: {e}"),
        }
    }
}

/// Built-in "Sonar way" profile as the default rule-activation set (issue
/// #22) — replaces the old ad-hoc "every registered rule at its default
/// severity" profile. There's no per-project profile assignment mechanism
/// in this codebase yet (see the note in `bin/server/src/ops.rs` — that's
/// deferred, same as it is for per-project *gate* assignment's later
/// phases), so this is the one profile every scan job uses.
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
        .chain(yunq_rules_rust::all_rules())
        .collect();
    let cross_rules = yunq_rules_owasp::all_cross_rules();
    let profile = yunq_rules_engine::sonar_way();
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

/// Resolves the project and pre-creates a placeholder analysis row *before*
/// the scan runs, so newly-saved issues/hotspots can be scoped to both
/// immediately instead of needing a separate backfill pass (see
/// `IssueScope`/`record_analysis_pending`). Best-effort: if either lookup
/// fails, the scan proceeds anyway with whatever scope was resolved (issues/
/// hotspots just land less scoped) rather than failing the job — same
/// "storage is already durable, gate/analysis bookkeeping is advisory"
/// contract `persist_gate_result` has always had.
async fn resolve_scan_scope(gate_storage: &PgIssueStorage, job: &ScanJob) -> IssueScope {
    let project_id = match gate_storage.ensure_project(job.project()).await {
        Ok(id) => id,
        Err(e) => {
            eprintln!("warning: could not resolve project {}: {e}", job.project());
            return IssueScope::default();
        }
    };

    let analysis_id = match gate_storage.record_analysis_pending(project_id, DEFAULT_BRANCH).await {
        Ok(id) => Some(id),
        Err(e) => {
            eprintln!("warning: could not pre-record analysis for {}: {e}", job.project());
            None
        }
    };

    IssueScope { project_id: Some(project_id), analysis_id }
}

/// Evaluates the project's assigned gate (or the built-in default, if none
/// was assigned) against this analysis' measures, and persists the outcome
/// so the status badge reflects a real result instead of a hardcoded
/// value. Best-effort: a failure here must not fail the scan job itself
/// (the issues/hotspots/metrics are already durable).
async fn persist_gate_result(
    gate_storage: &PgIssueStorage,
    job: &ScanJob,
    scope: IssueScope,
    report: &AnalysisReport,
) {
    let Some(project_id) = scope.project_id else {
        // `resolve_scan_scope` already logged why there's no project.
        return;
    };

    let gate =
        gate_storage.gate_for_project(project_id).await.unwrap_or_else(|_| yunq_rules_engine::default_gate());
    let evaluation = gate.evaluate(|key| report.measure(key));
    let lines_of_code = report.metrics().lines_of_code() as i64;
    let issue_total = report.metrics().issue_total() as i32;

    // If `resolve_scan_scope` already created the analysis row (the common
    // case), backfill its real metrics rather than creating a second row.
    let analysis_id = match scope.analysis_id {
        Some(id) => {
            if let Err(e) = gate_storage.finalize_analysis(id, lines_of_code, issue_total).await {
                eprintln!("warning: could not finalize analysis: {e}");
            }
            id
        }
        None => match gate_storage
            .record_analysis(project_id, DEFAULT_BRANCH, lines_of_code, issue_total)
            .await
        {
            Ok(id) => id,
            Err(e) => {
                eprintln!("warning: could not record analysis: {e}");
                return;
            }
        },
    };

    if let Err(e) = gate_storage.save_gate_result(analysis_id, &evaluation).await {
        eprintln!("warning: could not persist gate result: {e}");
    } else {
        println!("quality gate for {}: {}", job.project(), evaluation.status());
    }

    // Measure history / component tree (issue #26): persist this analysis'
    // full measure set — project-level and, where derivable from the
    // issues already in `report`, per-file — so the server's measure
    // history and component-tree endpoints have real data instead of
    // nothing. Best-effort, same rationale as the gate result above: a
    // failure here must not fail the scan job.
    if let Err(e) = gate_storage
        .save_measures(analysis_id, &report.all_measures(), &report.file_issue_measures())
        .await
    {
        eprintln!("warning: could not persist measures: {e}");
    }
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

    let scope = resolve_scan_scope(gate_storage, &job).await;

    let report = service
        .analyze_files_scoped(&sources, scope)
        .await
        .map_err(|e| QueueError(e.to_string()))?;
    println!(
        "scanned project {}: {} files, {} issues",
        job.project(),
        report.metrics().files_scanned(),
        report.metrics().issue_total()
    );

    persist_gate_result(gate_storage, &job, scope, &report).await;

    Ok(())
}
