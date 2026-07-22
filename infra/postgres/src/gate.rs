//! Outbound adapter: quality gate persistence — project → gate assignment,
//! the gate result of each analysis, and the "New Code" definition per
//! project/branch. Lives alongside `PgIssueStorage` (same pool, same
//! database) but in its own module since none of this is on the hot path of
//! issue search/workflow.

use sqlx::postgres::PgRow;
use sqlx::Row;
use yunq_rules_engine::{
    default_gate, BranchName, ComparisonOperator, Condition, ConditionStatus, GateEvaluation,
    GateResultReader, GateResultSummary, GateStatus, MetricKey, NewCodeDefinition, QualityGate,
    StorageError,
};

use crate::PgIssueStorage;

fn storage_err(e: impl std::fmt::Display) -> StorageError {
    StorageError(e.to_string())
}

fn operator_to_column(operator: ComparisonOperator) -> &'static str {
    match operator {
        ComparisonOperator::GreaterThan => "gt",
        ComparisonOperator::LessThan => "lt",
    }
}

fn operator_from_column(raw: &str) -> Result<ComparisonOperator, StorageError> {
    match raw {
        "gt" => Ok(ComparisonOperator::GreaterThan),
        "lt" => Ok(ComparisonOperator::LessThan),
        other => Err(StorageError(format!("invalid comparison operator {other:?}"))),
    }
}

fn gate_status_to_column(status: GateStatus) -> &'static str {
    match status {
        GateStatus::Passed => "passed",
        GateStatus::Failed => "failed",
    }
}

fn gate_status_from_column(raw: &str) -> Result<GateStatus, StorageError> {
    match raw {
        "passed" => Ok(GateStatus::Passed),
        "failed" => Ok(GateStatus::Failed),
        other => Err(StorageError(format!("invalid gate status {other:?}"))),
    }
}

/// The mode-specific payload of a `NewCodeDefinition`, split from its `kind`
/// discriminator so both can be stored as plain text columns without this
/// crate (or the pure core) taking on a serialization dependency.
fn new_code_definition_to_row(definition: &NewCodeDefinition) -> (&'static str, Option<String>) {
    match definition {
        NewCodeDefinition::PreviousAnalysis => ("previous_analysis", None),
        NewCodeDefinition::NumberOfDays(days) => ("number_of_days", Some(days.to_string())),
        NewCodeDefinition::ReferenceBranch(branch) => {
            ("reference_branch", Some(branch.as_str().to_string()))
        }
        NewCodeDefinition::SpecificAnalysis(id) => ("specific_analysis", Some(id.clone())),
    }
}

/// Rebuilds a `NewCodeDefinition` from its stored `(kind, param)` pair.
/// Pure and DB-free on purpose so the parsing rules are unit-testable
/// without a live database.
fn new_code_definition_from_row(
    kind: &str,
    param: Option<&str>,
) -> Result<NewCodeDefinition, StorageError> {
    match kind {
        "previous_analysis" => Ok(NewCodeDefinition::PreviousAnalysis),
        "number_of_days" => {
            let raw = param.ok_or_else(|| StorageError("number_of_days requires a param".into()))?;
            let days: u32 =
                raw.parse().map_err(|e| StorageError(format!("invalid day count {raw:?}: {e}")))?;
            Ok(NewCodeDefinition::NumberOfDays(days))
        }
        "reference_branch" => {
            let raw =
                param.ok_or_else(|| StorageError("reference_branch requires a param".into()))?;
            let branch = BranchName::new(raw).map_err(storage_err)?;
            Ok(NewCodeDefinition::ReferenceBranch(branch))
        }
        "specific_analysis" => {
            let raw =
                param.ok_or_else(|| StorageError("specific_analysis requires a param".into()))?;
            Ok(NewCodeDefinition::SpecificAnalysis(raw.to_string()))
        }
        other => Err(StorageError(format!("invalid new code definition kind {other:?}"))),
    }
}

impl PgIssueStorage {
    /// Looks up a project by key, creating it (with no gate assignment —
    /// resolved to the default gate at read time) on first sight. Idempotent:
    /// a project already on file is returned unchanged.
    pub async fn ensure_project(&self, key: &str) -> Result<i64, StorageError> {
        let row = sqlx::query(
            "INSERT INTO projects (key, name) VALUES ($1, $1)
             ON CONFLICT (key) DO UPDATE SET key = EXCLUDED.key
             RETURNING id",
        )
        .bind(key)
        .fetch_one(&self.pool)
        .await
        .map_err(storage_err)?;
        row.try_get::<i64, _>("id").map_err(storage_err)
    }

    /// The effective quality gate for a project: the one explicitly assigned
    /// to it, or the instance-wide default gate row, or (if neither row
    /// exists — a fresh database with migrations not yet seeded) the
    /// built-in `default_gate()` baked into the binary.
    pub async fn gate_for_project(&self, project_id: i64) -> Result<QualityGate, StorageError> {
        let assigned: Option<i64> =
            sqlx::query("SELECT gate_id FROM projects WHERE id = $1")
                .bind(project_id)
                .fetch_optional(&self.pool)
                .await
                .map_err(storage_err)?
                .map(|row: PgRow| row.try_get::<Option<i64>, _>("gate_id"))
                .transpose()
                .map_err(storage_err)?
                .flatten();

        let gate_id = match assigned {
            Some(id) => Some(id),
            None => sqlx::query("SELECT id FROM quality_gates WHERE is_default LIMIT 1")
                .fetch_optional(&self.pool)
                .await
                .map_err(storage_err)?
                .map(|row| row.try_get::<i64, _>("id"))
                .transpose()
                .map_err(storage_err)?,
        };

        let Some(gate_id) = gate_id else {
            return Ok(default_gate());
        };

        let name: String = sqlx::query("SELECT name FROM quality_gates WHERE id = $1")
            .bind(gate_id)
            .fetch_one(&self.pool)
            .await
            .map_err(storage_err)?
            .try_get("name")
            .map_err(storage_err)?;

        let rows = sqlx::query(
            "SELECT metric, operator, threshold FROM quality_gate_conditions WHERE gate_id = $1 ORDER BY id",
        )
        .bind(gate_id)
        .fetch_all(&self.pool)
        .await
        .map_err(storage_err)?;

        let mut gate = QualityGate::new(name);
        for row in &rows {
            let metric: String = row.try_get("metric").map_err(storage_err)?;
            let operator: String = row.try_get("operator").map_err(storage_err)?;
            let threshold: f64 = row.try_get("threshold").map_err(storage_err)?;
            let metric = MetricKey::new(&metric).map_err(storage_err)?;
            let operator = operator_from_column(&operator)?;
            gate = gate.with_condition(Condition::new(metric, operator, threshold));
        }
        Ok(gate)
    }

    /// Records one analysis run and returns its id — the unit the gate
    /// result (`save_gate_result`) is scoped to.
    pub async fn record_analysis(
        &self,
        project_id: i64,
        branch: &str,
        lines_of_code: i64,
        issue_total: i32,
    ) -> Result<i64, StorageError> {
        let row = sqlx::query(
            "INSERT INTO analyses (project_id, branch, lines_of_code, issue_total)
             VALUES ($1, $2, $3, $4) RETURNING id",
        )
        .bind(project_id)
        .bind(branch)
        .bind(lines_of_code)
        .bind(issue_total)
        .fetch_one(&self.pool)
        .await
        .map_err(storage_err)?;
        row.try_get::<i64, _>("id").map_err(storage_err)
    }

    /// Persists the outcome of evaluating a project's gate against one
    /// analysis, including the per-condition detail (metric, operator,
    /// threshold, measured value, status) so the badge and any future UI can
    /// explain *why* the gate passed or failed without recomputing anything.
    pub async fn save_gate_result(
        &self,
        analysis_id: i64,
        evaluation: &GateEvaluation,
    ) -> Result<(), StorageError> {
        let conditions: Vec<serde_json::Value> = evaluation
            .results()
            .iter()
            .map(|result| {
                let status = match result.status {
                    ConditionStatus::Passed => "passed",
                    ConditionStatus::Failed => "failed",
                    ConditionStatus::NoValue => "no_value",
                };
                serde_json::json!({
                    "metric": result.condition.metric().as_str(),
                    "operator": operator_to_column(result.condition.operator()),
                    "threshold": result.condition.threshold(),
                    "value": result.value,
                    "status": status,
                })
            })
            .collect();
        let conditions_json =
            serde_json::to_string(&conditions).map_err(|e| StorageError(e.to_string()))?;

        sqlx::query(
            "INSERT INTO analysis_gate_results (analysis_id, status, conditions)
             VALUES ($1, $2, $3::jsonb)
             ON CONFLICT (analysis_id) DO UPDATE SET status = EXCLUDED.status, conditions = EXCLUDED.conditions",
        )
        .bind(analysis_id)
        .bind(gate_status_to_column(evaluation.status()))
        .bind(conditions_json)
        .execute(&self.pool)
        .await
        .map_err(storage_err)?;
        Ok(())
    }

    /// The New Code definition that applies to a project's branch: a
    /// branch-specific override if one is stored, else the project-wide
    /// default, else SonarQube's own default (`PreviousAnalysis`).
    pub async fn resolve_new_code_definition(
        &self,
        project_id: i64,
        branch: &str,
    ) -> Result<NewCodeDefinition, StorageError> {
        let row = sqlx::query(
            "SELECT kind, param FROM new_code_definitions WHERE project_id = $1 AND branch = $2
             UNION ALL
             SELECT kind, param FROM new_code_definitions WHERE project_id = $1 AND branch IS NULL
             LIMIT 1",
        )
        .bind(project_id)
        .bind(branch)
        .fetch_optional(&self.pool)
        .await
        .map_err(storage_err)?;

        let Some(row) = row else {
            return Ok(NewCodeDefinition::PreviousAnalysis);
        };
        let kind: String = row.try_get("kind").map_err(storage_err)?;
        let param: Option<String> = row.try_get("param").map_err(storage_err)?;
        new_code_definition_from_row(&kind, param.as_deref())
    }

    /// Assigns a New Code definition to a project, optionally scoped to one
    /// branch (`None` sets the project-wide default).
    pub async fn set_new_code_definition(
        &self,
        project_id: i64,
        branch: Option<&str>,
        definition: &NewCodeDefinition,
    ) -> Result<(), StorageError> {
        let (kind, param) = new_code_definition_to_row(definition);
        sqlx::query(
            "INSERT INTO new_code_definitions (project_id, branch, kind, param)
             VALUES ($1, $2, $3, $4)
             ON CONFLICT (project_id, (COALESCE(branch, ''))) DO UPDATE
                SET kind = EXCLUDED.kind, param = EXCLUDED.param",
        )
        .bind(project_id)
        .bind(branch)
        .bind(kind)
        .bind(param)
        .execute(&self.pool)
        .await
        .map_err(storage_err)?;
        Ok(())
    }
}

impl PgIssueStorage {
    /// Creates the named gate if it doesn't exist yet, then replaces its
    /// full condition set — the write path behind
    /// `PUT /api/quality-gates/{name}`. Returns `(before, after)` condition
    /// lists for the audit log; `before` is empty when the gate is new.
    pub async fn upsert_quality_gate(
        &self,
        name: &str,
        conditions: &[(String, ComparisonOperator, f64)],
    ) -> Result<(Vec<(String, ComparisonOperator, f64)>, Vec<(String, ComparisonOperator, f64)>), StorageError>
    {
        let mut tx = self.pool.begin().await.map_err(storage_err)?;

        let gate_id: i64 = sqlx::query(
            "INSERT INTO quality_gates (name) VALUES ($1)
             ON CONFLICT (name) DO UPDATE SET name = EXCLUDED.name
             RETURNING id",
        )
        .bind(name)
        .fetch_one(&mut *tx)
        .await
        .map_err(storage_err)?
        .try_get("id")
        .map_err(storage_err)?;

        let before_rows = sqlx::query(
            "SELECT metric, operator, threshold FROM quality_gate_conditions
             WHERE gate_id = $1 ORDER BY id",
        )
        .bind(gate_id)
        .fetch_all(&mut *tx)
        .await
        .map_err(storage_err)?;
        let mut before = Vec::with_capacity(before_rows.len());
        for row in &before_rows {
            let metric: String = row.try_get("metric").map_err(storage_err)?;
            let operator: String = row.try_get("operator").map_err(storage_err)?;
            let threshold: f64 = row.try_get("threshold").map_err(storage_err)?;
            before.push((metric, operator_from_column(&operator)?, threshold));
        }

        sqlx::query("DELETE FROM quality_gate_conditions WHERE gate_id = $1")
            .bind(gate_id)
            .execute(&mut *tx)
            .await
            .map_err(storage_err)?;

        for (metric, operator, threshold) in conditions {
            sqlx::query(
                "INSERT INTO quality_gate_conditions (gate_id, metric, operator, threshold)
                 VALUES ($1, $2, $3, $4)",
            )
            .bind(gate_id)
            .bind(metric)
            .bind(operator_to_column(*operator))
            .bind(threshold)
            .execute(&mut *tx)
            .await
            .map_err(storage_err)?;
        }

        tx.commit().await.map_err(storage_err)?;
        Ok((before, conditions.to_vec()))
    }
}

impl GateResultReader for PgIssueStorage {
    async fn latest_gate_result(
        &self,
        project_key: &str,
    ) -> Result<Option<GateResultSummary>, StorageError> {
        let row = sqlx::query(
            "SELECT r.status, to_char(r.evaluated_at, 'YYYY-MM-DD\"T\"HH24:MI:SS.USZ') AS evaluated_at
             FROM analysis_gate_results r
             JOIN analyses a ON a.id = r.analysis_id
             JOIN projects p ON p.id = a.project_id
             WHERE p.key = $1
             ORDER BY a.id DESC
             LIMIT 1",
        )
        .bind(project_key)
        .fetch_optional(&self.pool)
        .await
        .map_err(storage_err)?;

        let Some(row) = row else { return Ok(None) };
        let status_raw: String = row.try_get("status").map_err(storage_err)?;
        let evaluated_at: String = row.try_get("evaluated_at").map_err(storage_err)?;
        Ok(Some(GateResultSummary { status: gate_status_from_column(&status_raw)?, evaluated_at }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_code_definition_roundtrips_through_kind_and_param() {
        let cases = vec![
            NewCodeDefinition::PreviousAnalysis,
            NewCodeDefinition::NumberOfDays(30),
            NewCodeDefinition::ReferenceBranch(BranchName::new("main").unwrap()),
            NewCodeDefinition::SpecificAnalysis("42".to_string()),
        ];
        for definition in cases {
            let (kind, param) = new_code_definition_to_row(&definition);
            let restored = new_code_definition_from_row(kind, param.as_deref()).unwrap();
            assert_eq!(restored, definition);
        }
    }

    #[test]
    fn number_of_days_without_a_param_is_rejected() {
        assert!(new_code_definition_from_row("number_of_days", None).is_err());
    }

    #[test]
    fn unknown_kind_is_rejected() {
        assert!(new_code_definition_from_row("bogus", None).is_err());
    }

    #[test]
    fn comparison_operator_roundtrips_through_column_encoding() {
        assert_eq!(
            operator_from_column(operator_to_column(ComparisonOperator::GreaterThan)).unwrap(),
            ComparisonOperator::GreaterThan
        );
        assert_eq!(
            operator_from_column(operator_to_column(ComparisonOperator::LessThan)).unwrap(),
            ComparisonOperator::LessThan
        );
        assert!(operator_from_column("bogus").is_err());
    }

    #[test]
    fn gate_status_roundtrips_through_column_encoding() {
        assert_eq!(
            gate_status_from_column(gate_status_to_column(GateStatus::Passed)).unwrap(),
            GateStatus::Passed
        );
        assert_eq!(
            gate_status_from_column(gate_status_to_column(GateStatus::Failed)).unwrap(),
            GateStatus::Failed
        );
        assert!(gate_status_from_column("bogus").is_err());
    }
}
