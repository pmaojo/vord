//! `--monorepo` scan mode: discovers every `yunq.toml` under the scan root
//! (`yunq_infra_fs::discover_projects`) and runs the existing per-project
//! scan pipeline once per discovered project, keeping each project's
//! results distinct in the rendered output rather than merging every
//! project's issues into one undifferentiated report.

use std::path::{Path, PathBuf};

use yunq_rules_engine::{GateStatus, NewCodeAnalysis, Severity};

use crate::output;

/// One project's outcome within a monorepo scan.
pub struct ProjectScanResult {
    pub project_path: PathBuf,
    pub project_key: Option<String>,
    pub report: yunq_rules_engine::AnalysisReport,
    pub gate: yunq_rules_engine::GateEvaluation,
    pub new_code: Option<NewCodeAnalysis>,
}

impl ProjectScanResult {
    /// The path to show the user, relative to the monorepo root when
    /// possible (absolute paths in multi-project output are noisy).
    pub fn display_path(&self, root: &Path) -> String {
        self.project_path.strip_prefix(root).unwrap_or(&self.project_path).display().to_string()
    }
}

/// `--monorepo`: discovers every yunq.toml-configured project under
/// `args.path` (`yunq_infra_fs::discover_projects`) and scans each
/// independently, reusing the same scan/baseline/gate machinery a
/// single-project `yunq scan` uses — just looped per project directory —
/// rather than flattening every project's issues into one incoherent
/// report. Coverage/JUnit/SARIF ingestion is intentionally out of scope
/// here: a single coverage/test/analysis report rarely maps cleanly onto
/// several independent projects in one invocation, so those flags are a
/// single-project-only feature for now.
pub async fn run(args: &crate::ScanArgs) -> anyhow::Result<std::process::ExitCode> {
    let root = &args.path;
    let projects = yunq_infra_fs::discover_projects(root);
    if projects.is_empty() {
        anyhow::bail!(
            "--monorepo: no yunq.toml found under {} (each project needs its own yunq.toml to be discovered)",
            root.display()
        );
    }

    let ci = crate::resolve_ci_context();
    let context = crate::resolve_context(args, None, &ci);

    let mut results = Vec::with_capacity(projects.len());
    for project_dir in &projects {
        let config = yunq_infra_fs::YunqConfig::load_from_dir(project_dir).unwrap_or_default();
        let source_dirs = config.analysis.sources.clone().unwrap_or_default();
        let exclusions = config.analysis.exclusions.clone().unwrap_or_default();

        let cache = (!args.no_cache).then(|| {
            std::sync::Arc::new(yunq_infra_fs::FileAnalysisCache::open(project_dir.join(".yunq-cache.json")))
        });
        // Each project's own `[duplication]` settings, so a monorepo can
        // hold packages with different tolerances rather than one blanket
        // policy imposed by the root.
        let report = yunq_cli::scan_with_project_config(
            project_dir,
            cache.clone(),
            &source_dirs,
            &exclusions,
            &config.duplication,
            &config.architecture,
        )
        .await?;
        if let Some(cache) = &cache
            && let Err(e) = cache.persist()
        {
            eprintln!("warning: could not persist analysis cache for {}: {e}", project_dir.display());
        }

        let new_code = crate::classify_new_code(project_dir, args.no_baseline, &report);
        let gate = yunq_cli::default_quality_gate()
            .evaluate(|key| new_code.as_ref().and_then(|nc| nc.measure(key)).or_else(|| report.measure(key)));

        results.push(ProjectScanResult {
            project_path: project_dir.clone(),
            project_key: config.project.key,
            report,
            gate,
            new_code,
        });
    }

    report_monorepo_status(args, &context, &results).await;

    let shared_context = context.to_dto();
    match args.output.format {
        crate::Format::Text => print!("{}", render_text(root, &results, &shared_context)),
        crate::Format::Json => println!("{}", render_json(root, &results, &shared_context)?),
    }

    let threshold = crate::parse_fail_on_threshold(args.fail_on.clone())?;
    let failed = any_project_failed(&results, threshold, args.enforce_gate);
    Ok(if failed { std::process::ExitCode::from(3) } else { std::process::ExitCode::SUCCESS })
}

/// Posts one aggregate commit status for the whole monorepo scan — a commit
/// gets exactly one "yunq" status regardless of how many projects it
/// contains, so per-project statuses would just clobber each other.
async fn report_monorepo_status(
    args: &crate::ScanArgs,
    context: &crate::ResolvedContext,
    results: &[ProjectScanResult],
) {
    use yunq_rules_engine::{AlmStatusReporter, CommitStatus, CommitStatusState};

    let Some(sha_str) = &context.commit_sha else { return };
    let Ok(sha) = yunq_rules_engine::CommitSha::new(sha_str) else { return };
    let Some(reporter) = crate::github_reporter(args, context) else { return };

    let total_issues: usize = results.iter().map(|r| r.report.issues().len()).sum();
    let failed_projects = results.iter().filter(|r| r.gate.status() == GateStatus::Failed).count();
    let state = if failed_projects == 0 { CommitStatusState::Success } else { CommitStatusState::Failure };
    let desc = format!(
        "{}/{} projects passed gate — {total_issues} issues found",
        results.len() - failed_projects,
        results.len(),
    );
    let status = CommitStatus::new(state, desc);
    if let Err(e) = reporter.report_commit_status(&sha, &status).await {
        eprintln!("warning: could not report commit status to GitHub: {e}");
    }
}

/// Whether any project's result should fail the overall `yunq scan`
/// invocation — the same severity-threshold / gate-enforcement rules
/// `exit_code` applies to a single-project scan, OR'd across every project.
pub fn any_project_failed(
    results: &[ProjectScanResult],
    threshold: Option<Severity>,
    enforce_gate: bool,
) -> bool {
    results.iter().any(|result| {
        let breached =
            threshold.zip(result.report.max_severity()).is_some_and(|(t, max)| max >= t);
        let gate_failed = enforce_gate && result.gate.status() == GateStatus::Failed;
        breached || gate_failed
    })
}

/// Renders every project's result as one JSON array — a single valid JSON
/// document, not several reports concatenated — with clear per-project
/// attribution (`project_path`/`project_key`) alongside each project's
/// existing `ReportDto` shape. `shared_context` carries the scan-wide
/// `--branch`/`--pr` (the same commit is being analyzed across every
/// project); each project's own key overrides `shared_context.project`.
pub fn render_json(
    root: &Path,
    results: &[ProjectScanResult],
    shared_context: &output::ScanContextDto,
) -> serde_json::Result<String> {
    #[derive(serde::Serialize)]
    struct ProjectDto {
        project_path: String,
        project_key: Option<String>,
        report: output::ReportDto,
    }

    let dtos: Vec<ProjectDto> = results
        .iter()
        .map(|result| {
            let context = output::ScanContextDto {
                project: result.project_key.clone().or_else(|| shared_context.project.clone()),
                branch: shared_context.branch.clone(),
                pull_request: shared_context.pull_request,
            };
            ProjectDto {
                project_path: result.display_path(root),
                project_key: result.project_key.clone(),
                report: output::ReportDto::build(
                    &result.report,
                    &result.gate,
                    result.new_code.as_ref(),
                    None,
                    None,
                    context,
                ),
            }
        })
        .collect();
    serde_json::to_string_pretty(&dtos)
}

/// Renders every project's result as plain text, one banner-delimited
/// section per project.
pub fn render_text(
    root: &Path,
    results: &[ProjectScanResult],
    shared_context: &output::ScanContextDto,
) -> String {
    let mut out = String::new();
    for result in results {
        let label = result.project_key.as_deref().unwrap_or("(no project key)");
        out.push_str(&format!(
            "\n==== project: {} [{label}] ====\n",
            result.display_path(root),
        ));
        let context = output::ScanContextDto {
            project: result.project_key.clone().or_else(|| shared_context.project.clone()),
            branch: shared_context.branch.clone(),
            pull_request: shared_context.pull_request,
        };
        out.push_str(&output::render_text(&result.report, &result.gate, result.new_code.as_ref(), None, None, &context));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use yunq_rules_engine::{AnalyzerService, Condition, ComparisonOperator, MetricKey, QualityGate};
    use yunq_infra_memory::{InMemoryIssueStorage, InMemoryMetricsTracker};

    fn empty_report() -> yunq_rules_engine::AnalysisReport {
        futures::executor::block_on(async {
            let service = AnalyzerService::new(
                yunq_rules_engine::QualityProfile::from_activations("empty", std::iter::empty()),
                InMemoryIssueStorage::new(),
                InMemoryMetricsTracker::new(),
            );
            service.analyze_files(&[]).await.unwrap()
        })
    }

    fn passing_gate() -> yunq_rules_engine::GateEvaluation {
        let metric = MetricKey::new("blocker_issues").unwrap();
        QualityGate::new("test").with_condition(Condition::new(metric, ComparisonOperator::GreaterThan, 0.0)).evaluate(|_| Some(0.0))
    }

    #[test]
    fn no_project_fails_when_nothing_breaches_thresholds() {
        let results = vec![ProjectScanResult {
            project_path: PathBuf::from("/root/api"),
            project_key: Some("api".to_string()),
            report: empty_report(),
            gate: passing_gate(),
            new_code: None,
        }];
        assert!(!any_project_failed(&results, None, true));
    }

    #[test]
    fn display_path_is_relative_to_the_monorepo_root() {
        let result = ProjectScanResult {
            project_path: PathBuf::from("/root/services/api"),
            project_key: None,
            report: empty_report(),
            gate: passing_gate(),
            new_code: None,
        };
        assert_eq!(result.display_path(Path::new("/root")), "services/api");
    }
}
