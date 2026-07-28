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

use crate::{PgAnalysisStore, PgConfigStore};

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

/// The gate *definition* a project resolves to — configuration, read
/// during an analysis but written by administrators.
impl PgConfigStore {
    pub async fn gate_for_project(&self, project_id: i64) -> Result<QualityGate, StorageError> {
        let Some(gate_id) = crate::shared::resolved_gate_id(&self.pool, project_id).await? else {
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
}

/// The analysis lifecycle and the results one run produces.
impl PgAnalysisStore {
    /// Looks up a project by key, creating it on first sight. Idempotent.
    /// Lives here because creating the project is the first step of
    /// recording an analysis against it; the configuration context reaches
    /// the same helper internally when a setting names a project that has
    /// not been scanned yet.
    pub async fn ensure_project(&self, key: &str) -> Result<i64, StorageError> {
        crate::shared::ensure_project(&self.pool, key).await
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

    /// Inserts a placeholder analysis row (`lines_of_code`/`issue_total`
    /// both 0) *before* a scan runs, so the worker has a real `analysis_id`
    /// to scope newly-saved issues/hotspots to as they're persisted, rather
    /// than only being able to scope them to a project. Pair with
    /// [`Self::finalize_analysis`] once the scan's `AnalysisReport` is
    /// available, to backfill the real metrics onto the same row.
    pub async fn record_analysis_pending(
        &self,
        project_id: i64,
        branch: &str,
    ) -> Result<i64, StorageError> {
        self.record_analysis(project_id, branch, 0, 0).await
    }

    /// Backfills the real `lines_of_code`/`issue_total` onto an analysis row
    /// created by [`Self::record_analysis_pending`], once the scan that
    /// produced them has finished.
    pub async fn finalize_analysis(
        &self,
        analysis_id: i64,
        lines_of_code: i64,
        issue_total: i32,
    ) -> Result<(), StorageError> {
        sqlx::query("UPDATE analyses SET lines_of_code = $1, issue_total = $2 WHERE id = $3")
            .bind(lines_of_code)
            .bind(issue_total)
            .bind(analysis_id)
            .execute(&self.pool)
            .await
            .map_err(storage_err)?;
        Ok(())
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
    /// default, else the instance-wide global default (if one is set), else
    /// the built-in default (`PreviousAnalysis`).
    pub async fn resolve_new_code_definition(
        &self,
        project_id: i64,
        branch: &str,
    ) -> Result<NewCodeDefinition, StorageError> {
        let row = sqlx::query(
            "SELECT kind, param FROM new_code_definitions WHERE project_id = $1 AND branch = $2
             UNION ALL
             SELECT kind, param FROM new_code_definitions WHERE project_id = $1 AND branch IS NULL
             UNION ALL
             SELECT kind, param FROM global_new_code_definition WHERE id = 1
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

    /// The instance-wide default New Code definition, if one has been set —
    /// distinct from `resolve_new_code_definition`'s fully-resolved result,
    /// which also folds in any project/branch override and falls back to
    /// `PreviousAnalysis` rather than reporting "unset".
    pub async fn global_new_code_definition(&self) -> Result<Option<NewCodeDefinition>, StorageError> {
        let row = sqlx::query("SELECT kind, param FROM global_new_code_definition WHERE id = 1")
            .fetch_optional(&self.pool)
            .await
            .map_err(storage_err)?;
        let Some(row) = row else {
            return Ok(None);
        };
        let kind: String = row.try_get("kind").map_err(storage_err)?;
        let param: Option<String> = row.try_get("param").map_err(storage_err)?;
        new_code_definition_from_row(&kind, param.as_deref()).map(Some)
    }

    /// Sets the instance-wide default New Code definition, applied to any
    /// project/branch with no override of its own.
    pub async fn set_global_new_code_definition(
        &self,
        definition: &NewCodeDefinition,
    ) -> Result<(), StorageError> {
        let (kind, param) = new_code_definition_to_row(definition);
        sqlx::query(
            "INSERT INTO global_new_code_definition (id, kind, param)
             VALUES (1, $1, $2)
             ON CONFLICT (id) DO UPDATE
                SET kind = EXCLUDED.kind, param = EXCLUDED.param, updated_at = now()",
        )
        .bind(kind)
        .bind(param)
        .execute(&self.pool)
        .await
        .map_err(storage_err)?;
        Ok(())
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

    /// `resolve_new_code_definition`, reached from a project key instead of
    /// an id already in hand — the read path an admin API takes, where a
    /// project that has never been scanned is a legitimate "use the
    /// built-in default" outcome rather than something to create a row for.
    pub async fn resolve_new_code_definition_by_key(
        &self,
        project_key: &str,
        branch: &str,
    ) -> Result<NewCodeDefinition, StorageError> {
        let Some(project_id) = crate::shared::find_project_id(&self.pool, project_key).await? else {
            return Ok(NewCodeDefinition::PreviousAnalysis);
        };
        self.resolve_new_code_definition(project_id, branch).await
    }

    /// `set_new_code_definition`, reached from a project key instead of an
    /// id already in hand — the write path an admin API takes, where
    /// naming a project for the first time (e.g. before its first scan)
    /// should still succeed rather than requiring the project to already
    /// exist.
    pub async fn set_new_code_definition_by_key(
        &self,
        project_key: &str,
        branch: Option<&str>,
        definition: &NewCodeDefinition,
    ) -> Result<(), StorageError> {
        let project_id = crate::shared::ensure_project(&self.pool, project_key).await?;
        self.set_new_code_definition(project_id, branch, definition).await
    }
}

fn rows_to_conditions(rows: &[PgRow]) -> Result<Vec<(String, ComparisonOperator, f64)>, StorageError> {
    let mut conditions = Vec::with_capacity(rows.len());
    for row in rows {
        let metric: String = row.try_get("metric").map_err(storage_err)?;
        let operator: String = row.try_get("operator").map_err(storage_err)?;
        let threshold: f64 = row.try_get("threshold").map_err(storage_err)?;
        conditions.push((metric, operator_from_column(&operator)?, threshold));
    }
    Ok(conditions)
}

impl PgConfigStore {
    /// Replaces the full condition set of a gate: deletes all existing rows,
    /// then inserts `conditions` in order.
    async fn replace_gate_conditions(
        tx: &mut sqlx::PgConnection,
        gate_id: i64,
        conditions: &[(String, ComparisonOperator, f64)],
    ) -> Result<(), StorageError> {
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
        Ok(())
    }

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
        let before = rows_to_conditions(&before_rows)?;

        Self::replace_gate_conditions(&mut tx, gate_id, conditions).await?;

        tx.commit().await.map_err(storage_err)?;
        Ok((before, conditions.to_vec()))
    }
}

impl GateResultReader for PgAnalysisStore {
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

/// `#[ignore]`d by default so `cargo test` needs no database; run explicitly
/// with `cargo test -p yunq-infra-postgres -- --ignored` against
/// `DATABASE_URL`, same convention as `lib.rs`'s `live_db_tests` module.
///
/// `resolve_new_code_definition`'s full four-tier precedence
/// (branch > project > global > built-in `PreviousAnalysis`) — including the
/// project/branch tiers that predate this module and had no live coverage
/// of their own until now — was never exercised against a real database
/// before; these are the first.
#[cfg(test)]
mod live_db_tests {
    use super::*;
    use crate::PgAnalysisStore;

    async fn connected_storage() -> PgAnalysisStore {
        let database_url = std::env::var("DATABASE_URL")
            .unwrap_or_else(|_| "postgres://yunq:yunq@localhost:5432/yunq".to_string());
        let storage = PgAnalysisStore::connect_lazy(&database_url).unwrap();
        storage.migrate().await.unwrap();
        storage
    }

    fn unique_key(prefix: &str) -> String {
        format!(
            "{prefix}-{}",
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        )
    }

    /// Clears any prior run's global default so each test starts from a
    /// known "unset" state — the global row is a singleton shared by every
    /// test in this module (and, in principle, every project on the
    /// instance), unlike the per-project rows the rest of this file's tests
    /// isolate with a unique project key.
    async fn clear_global(storage: &PgAnalysisStore) {
        sqlx::query("DELETE FROM global_new_code_definition WHERE id = 1")
            .execute(storage.pool())
            .await
            .unwrap();
    }

    #[tokio::test]
    #[ignore = "requires a live Postgres; see module docs"]
    async fn global_default_is_none_until_set() {
        // The global row is a singleton shared across this whole module (and
        // in principle the instance), so tests that touch it — unlike the
        // per-project ones below, which isolate via a unique project key —
        // need the same whole-table lock `retention.rs`'s live tests use.
        let _guard = crate::shared::WHOLE_TABLE_LOCK.lock().await;
        let storage = connected_storage().await;
        clear_global(&storage).await;
        assert_eq!(storage.global_new_code_definition().await.unwrap(), None);
    }

    #[tokio::test]
    #[ignore = "requires a live Postgres; see module docs"]
    async fn global_default_roundtrips_and_upserts() {
        let _guard = crate::shared::WHOLE_TABLE_LOCK.lock().await;
        let storage = connected_storage().await;
        clear_global(&storage).await;

        storage.set_global_new_code_definition(&NewCodeDefinition::NumberOfDays(14)).await.unwrap();
        assert_eq!(
            storage.global_new_code_definition().await.unwrap(),
            Some(NewCodeDefinition::NumberOfDays(14))
        );

        // Setting it again replaces rather than duplicating the singleton row.
        storage
            .set_global_new_code_definition(&NewCodeDefinition::ReferenceBranch(
                BranchName::new("develop").unwrap(),
            ))
            .await
            .unwrap();
        assert_eq!(
            storage.global_new_code_definition().await.unwrap(),
            Some(NewCodeDefinition::ReferenceBranch(BranchName::new("develop").unwrap()))
        );

        clear_global(&storage).await;
    }

    #[tokio::test]
    #[ignore = "requires a live Postgres; see module docs"]
    async fn resolve_falls_back_through_all_four_tiers_in_precedence_order() {
        let _guard = crate::shared::WHOLE_TABLE_LOCK.lock().await;
        let storage = connected_storage().await;
        clear_global(&storage).await;
        let key = unique_key("gate-precedence");
        let project_id = storage.ensure_project(&key).await.unwrap();

        // 1. Nothing set anywhere: the built-in default.
        assert_eq!(
            storage.resolve_new_code_definition(project_id, "main").await.unwrap(),
            NewCodeDefinition::PreviousAnalysis
        );

        // 2. Global default set: it wins over the built-in default.
        storage.set_global_new_code_definition(&NewCodeDefinition::NumberOfDays(90)).await.unwrap();
        assert_eq!(
            storage.resolve_new_code_definition(project_id, "main").await.unwrap(),
            NewCodeDefinition::NumberOfDays(90)
        );

        // 3. Project-wide default set: it wins over the global default.
        storage
            .set_new_code_definition(project_id, None, &NewCodeDefinition::NumberOfDays(30))
            .await
            .unwrap();
        assert_eq!(
            storage.resolve_new_code_definition(project_id, "main").await.unwrap(),
            NewCodeDefinition::NumberOfDays(30)
        );
        // A different, unconfigured branch still only sees the project
        // default (and would fall through to global/built-in if that
        // weren't set) — the project default isn't branch-specific.
        assert_eq!(
            storage.resolve_new_code_definition(project_id, "feature/x").await.unwrap(),
            NewCodeDefinition::NumberOfDays(30)
        );

        // 4. Branch-specific override set: it wins over everything else,
        // but only for its own branch.
        storage
            .set_new_code_definition(
                project_id,
                Some("main"),
                &NewCodeDefinition::ReferenceBranch(BranchName::new("develop").unwrap()),
            )
            .await
            .unwrap();
        assert_eq!(
            storage.resolve_new_code_definition(project_id, "main").await.unwrap(),
            NewCodeDefinition::ReferenceBranch(BranchName::new("develop").unwrap())
        );
        assert_eq!(
            storage.resolve_new_code_definition(project_id, "feature/x").await.unwrap(),
            NewCodeDefinition::NumberOfDays(30)
        );

        sqlx::query("DELETE FROM projects WHERE id = $1").bind(project_id).execute(storage.pool()).await.unwrap();
        clear_global(&storage).await;
    }
}
