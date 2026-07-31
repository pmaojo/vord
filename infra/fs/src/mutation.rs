//! Mutation-testing report ingestion (inbound adapter). Parses the Stryker
//! "Mutation Testing Elements" JSON report schema — the format StrykerJS,
//! Stryker.NET and Infection (via its Stryker-format exporter) all emit —
//! into a [`MutationSummary`]. One importer, same relationship SARIF has to
//! static-analysis tools: yunq runs no mutants itself, it aggregates
//! another tool's kill/survive verdicts into a measure the quality gate can
//! act on.
//!
//! Schema: <https://github.com/stryker-mutator/mutation-testing-elements/blob/master/packages/report-schema/src/mutation-testing-report-schema.json>

use std::collections::BTreeMap;

use serde::Deserialize;
use yunq_rules_engine::MutationSummary;

#[derive(Debug, thiserror::Error)]
pub enum MutationParseError {
    #[error("malformed mutation testing report JSON: {0}")]
    Malformed(String),
}

#[derive(Deserialize)]
struct MutationTestingReport {
    #[serde(default)]
    files: BTreeMap<String, MutationFile>,
}

#[derive(Deserialize)]
struct MutationFile {
    #[serde(default)]
    mutants: Vec<Mutant>,
}

#[derive(Deserialize)]
struct Mutant {
    status: MutantStatus,
}

/// The report schema's `status` enum, verbatim.
#[derive(Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
enum MutantStatus {
    Killed,
    Survived,
    NoCoverage,
    CompileError,
    RuntimeError,
    Timeout,
    Ignored,
    Pending,
}

/// Parses a Stryker Mutation Testing Elements JSON report (StrykerJS'
/// `reports/mutation/mutation.json`, Stryker.NET's equivalent, or an
/// Infection report exported in this format) into a [`MutationSummary`].
///
/// Every mutant's `status` folds into exactly one counter — see
/// [`MutantStatus`] for the schema's own enum — matching the score formula
/// Stryker itself uses (detected over `killed + timeout + survived +
/// no_coverage`; `Ignored`/`CompileError`/`RuntimeError`/`Pending` count
/// toward neither).
pub fn parse_mutation_report(content: &str) -> Result<MutationSummary, MutationParseError> {
    let report: MutationTestingReport =
        serde_json::from_str(content).map_err(|e| MutationParseError::Malformed(e.to_string()))?;

    let mut summary = MutationSummary::default();
    for file in report.files.values() {
        for mutant in &file.mutants {
            summary.total_mutants += 1;
            match mutant.status {
                MutantStatus::Killed => summary.killed_mutants += 1,
                MutantStatus::Survived => summary.survived_mutants += 1,
                MutantStatus::NoCoverage => summary.no_coverage_mutants += 1,
                MutantStatus::Timeout => summary.timeout_mutants += 1,
                MutantStatus::Ignored => summary.ignored_mutants += 1,
                MutantStatus::CompileError | MutantStatus::RuntimeError => {
                    summary.error_mutants += 1
                }
                MutantStatus::Pending => summary.pending_mutants += 1,
            }
        }
    }
    Ok(summary)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn report(mutants: &str) -> String {
        format!(
            r#"{{"schemaVersion":"1.7","thresholds":{{"high":80,"low":60}},"files":{{"src/a.ts":{{"language":"typescript","source":"","mutants":[{mutants}]}}}}}}"#
        )
    }

    fn mutant(status: &str) -> String {
        format!(
            r#"{{"id":"1","mutatorName":"ConditionalExpression","status":"{status}","location":{{"start":{{"line":1,"column":1}},"end":{{"line":1,"column":2}}}}}}"#
        )
    }

    #[test]
    fn counts_every_status_into_its_own_bucket() {
        let mutants = [
            mutant("Killed"),
            mutant("Killed"),
            mutant("Survived"),
            mutant("NoCoverage"),
            mutant("Timeout"),
            mutant("Ignored"),
            mutant("CompileError"),
            mutant("RuntimeError"),
            mutant("Pending"),
        ]
        .join(",");
        let summary = parse_mutation_report(&report(&mutants)).unwrap();

        assert_eq!(summary.total_mutants, 9);
        assert_eq!(summary.killed_mutants, 2);
        assert_eq!(summary.survived_mutants, 1);
        assert_eq!(summary.no_coverage_mutants, 1);
        assert_eq!(summary.timeout_mutants, 1);
        assert_eq!(summary.ignored_mutants, 1);
        assert_eq!(summary.error_mutants, 2);
        assert_eq!(summary.pending_mutants, 1);
        // detected = killed(2) + timeout(1) = 3; valid = 3 + survived(1) + no_coverage(1) = 5.
        assert_eq!(summary.mutation_score(), Some(60.0));
    }

    #[test]
    fn merges_mutants_across_several_files() {
        let content = r#"{"schemaVersion":"1.7","thresholds":{"high":80,"low":60},"files":{
            "src/a.ts":{"language":"typescript","source":"","mutants":[{"id":"1","mutatorName":"m","status":"Killed","location":{"start":{"line":1,"column":1},"end":{"line":1,"column":2}}}]},
            "src/b.ts":{"language":"typescript","source":"","mutants":[{"id":"2","mutatorName":"m","status":"Survived","location":{"start":{"line":1,"column":1},"end":{"line":1,"column":2}}}]}
        }}"#;
        let summary = parse_mutation_report(content).unwrap();
        assert_eq!(summary.total_mutants, 2);
        assert_eq!(summary.killed_mutants, 1);
        assert_eq!(summary.survived_mutants, 1);
    }

    #[test]
    fn a_report_with_no_files_yields_a_zeroed_summary_with_no_score() {
        let summary = parse_mutation_report(
            r#"{"schemaVersion":"1.7","thresholds":{"high":80,"low":60},"files":{}}"#,
        )
        .unwrap();
        assert_eq!(summary.total_mutants, 0);
        assert_eq!(summary.mutation_score(), None);
    }

    #[test]
    fn malformed_json_is_reported_as_an_error() {
        assert!(parse_mutation_report("not json").is_err());
    }

    #[test]
    fn unknown_status_value_is_reported_as_an_error_not_silently_dropped() {
        let content = report(&mutant("SomeFutureStatus"));
        assert!(parse_mutation_report(&content).is_err());
    }
}
