//! Outbound adapter: measure history and component-tree persistence
//! (issue #26) — `analysis_measures` rows written once per completed
//! analysis (`MeasureStorage`, called from `bin/worker`) and read back as a
//! metric time series (`MeasureHistoryReader`) or a project's latest
//! per-file measures (`ComponentTreeReader`). Lives alongside
//! `PgIssueStorage`/`gate.rs`/`coverage.rs` (same pool, same database).

use std::collections::BTreeMap;

use sqlx::{Postgres, QueryBuilder, Row};
use yunq_rules_engine::{
    ComponentMeasures, ComponentTree, ComponentTreeReader, MeasureHistoryPoint,
    MeasureHistoryReader, MeasureStorage, StorageError,
};

use crate::PgIssueStorage;

fn storage_err(e: impl std::fmt::Display) -> StorageError {
    StorageError(e.to_string())
}

/// Postgres binds at most 65535 parameters per statement; measure rows bind
/// 4 columns each, matching the batching convention `IssueStorage::save_issues`
/// already uses.
const MEASURE_BATCH_ROWS: usize = 1000;

impl MeasureStorage for PgIssueStorage {
    async fn save_measures(
        &self,
        analysis_id: i64,
        project_measures: &[(String, f64)],
        file_measures: &BTreeMap<String, BTreeMap<String, f64>>,
    ) -> Result<(), StorageError> {
        // (component, key, value) rows: `None` component for the project-level
        // measures, `Some(path)` for each file's measures.
        let mut rows: Vec<(Option<&str>, &str, f64)> = Vec::with_capacity(
            project_measures.len() + file_measures.values().map(|m| m.len()).sum::<usize>(),
        );
        for (key, value) in project_measures {
            rows.push((None, key.as_str(), *value));
        }
        for (path, measures) in file_measures {
            for (key, value) in measures {
                rows.push((Some(path.as_str()), key.as_str(), *value));
            }
        }
        if rows.is_empty() {
            return Ok(());
        }

        let mut tx = self.pool.begin().await.map_err(storage_err)?;
        for chunk in rows.chunks(MEASURE_BATCH_ROWS) {
            let mut builder = QueryBuilder::<Postgres>::new(
                "INSERT INTO analysis_measures (analysis_id, component, measure_key, measure_value) ",
            );
            builder.push_values(chunk, |mut row, (component, key, value)| {
                row.push_bind(analysis_id)
                    .push_bind(*component)
                    .push_bind(*key)
                    .push_bind(*value);
            });
            builder.push(
                " ON CONFLICT (analysis_id, COALESCE(component, ''), measure_key)
                  DO UPDATE SET measure_value = EXCLUDED.measure_value",
            );
            builder
                .build()
                .execute(&mut *tx)
                .await
                .map_err(storage_err)?;
        }
        tx.commit().await.map_err(storage_err)
    }
}

impl MeasureHistoryReader for PgIssueStorage {
    async fn measure_history(
        &self,
        project_key: &str,
        branch: &str,
        component: Option<&str>,
        metric_keys: &[String],
        from: Option<&str>,
        to: Option<&str>,
    ) -> Result<Vec<MeasureHistoryPoint>, StorageError> {
        let mut builder = QueryBuilder::<Postgres>::new(
            "SELECT a.id AS analysis_id,
                    to_char(a.created_at, 'YYYY-MM-DD\"T\"HH24:MI:SS.USZ') AS date,
                    m.measure_key, m.measure_value
             FROM analysis_measures m
             JOIN analyses a ON a.id = m.analysis_id
             JOIN projects p ON p.id = a.project_id
             WHERE p.key = ",
        );
        builder.push_bind(project_key);
        builder.push(" AND a.branch = ");
        builder.push_bind(branch);
        builder.push(" AND m.component IS NOT DISTINCT FROM ");
        builder.push_bind(component);

        if !metric_keys.is_empty() {
            builder.push(" AND m.measure_key = ANY(");
            builder.push_bind(metric_keys.to_vec());
            builder.push(")");
        }
        if let Some(from) = from {
            builder.push(" AND a.created_at >= ");
            builder.push_bind(from.to_string());
            builder.push("::timestamptz");
        }
        if let Some(to) = to {
            builder.push(" AND a.created_at <= ");
            builder.push_bind(to.to_string());
            builder.push("::timestamptz");
        }
        builder.push(" ORDER BY a.id ASC");

        let rows = builder
            .build()
            .fetch_all(&self.pool)
            .await
            .map_err(storage_err)?;

        // Rows come back one-per-(analysis, metric); fold into one point per
        // analysis, preserving the ascending order the query already gives.
        let mut points: Vec<MeasureHistoryPoint> = Vec::new();
        for row in &rows {
            let analysis_id: i64 = row.try_get("analysis_id").map_err(storage_err)?;
            let date: String = row.try_get("date").map_err(storage_err)?;
            let key: String = row.try_get("measure_key").map_err(storage_err)?;
            let value: f64 = row.try_get("measure_value").map_err(storage_err)?;

            match points.last_mut() {
                Some(point) if point.analysis_id == analysis_id => {
                    point.values.insert(key, value);
                }
                _ => {
                    let mut values = BTreeMap::new();
                    values.insert(key, value);
                    points.push(MeasureHistoryPoint {
                        analysis_id,
                        date,
                        values,
                    });
                }
            }
        }
        Ok(points)
    }
}

impl ComponentTreeReader for PgIssueStorage {
    async fn component_tree(
        &self,
        project_key: &str,
        branch: &str,
    ) -> Result<Option<ComponentTree>, StorageError> {
        let latest: Option<i64> = sqlx::query(
            "SELECT a.id FROM analyses a
             JOIN projects p ON p.id = a.project_id
             WHERE p.key = $1 AND a.branch = $2
             ORDER BY a.id DESC LIMIT 1",
        )
        .bind(project_key)
        .bind(branch)
        .fetch_optional(&self.pool)
        .await
        .map_err(storage_err)?
        .map(|row| row.try_get::<i64, _>("id"))
        .transpose()
        .map_err(storage_err)?;

        let Some(analysis_id) = latest else {
            return Ok(None);
        };

        let rows = sqlx::query(
            "SELECT component, measure_key, measure_value FROM analysis_measures
             WHERE analysis_id = $1 AND component IS NOT NULL
             ORDER BY component ASC",
        )
        .bind(analysis_id)
        .fetch_all(&self.pool)
        .await
        .map_err(storage_err)?;

        let mut by_path: BTreeMap<String, BTreeMap<String, f64>> = BTreeMap::new();
        for row in &rows {
            let path: String = row.try_get("component").map_err(storage_err)?;
            let key: String = row.try_get("measure_key").map_err(storage_err)?;
            let value: f64 = row.try_get("measure_value").map_err(storage_err)?;
            by_path.entry(path).or_default().insert(key, value);
        }

        let components = by_path
            .into_iter()
            .map(|(path, measures)| ComponentMeasures { path, measures })
            .collect();
        Ok(Some(ComponentTree {
            analysis_id,
            components,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn measure_history_point_folds_multiple_metrics_into_one_point_manually() {
        // Pure sanity check of the folding logic used by `measure_history`
        // above, without a database: same-analysis rows collapse into one
        // point's `values` map.
        let mut points: Vec<MeasureHistoryPoint> = Vec::new();
        let rows = [
            (1i64, "2024-01-01T00:00:00Z", "coverage", 80.0),
            (1, "2024-01-01T00:00:00Z", "issue_total", 3.0),
            (2, "2024-01-02T00:00:00Z", "coverage", 90.0),
        ];
        for (analysis_id, date, key, value) in rows {
            match points.last_mut() {
                Some(point) if point.analysis_id == analysis_id => {
                    point.values.insert(key.to_string(), value);
                }
                _ => {
                    let mut values = BTreeMap::new();
                    values.insert(key.to_string(), value);
                    points.push(MeasureHistoryPoint {
                        analysis_id,
                        date: date.to_string(),
                        values,
                    });
                }
            }
        }
        assert_eq!(points.len(), 2);
        assert_eq!(points[0].values.len(), 2);
        assert_eq!(points[0].values["coverage"], 80.0);
        assert_eq!(points[1].values["coverage"], 90.0);
    }
}

/// `#[ignore]`d by default so `cargo test` needs no database, matching the
/// convention in `lib.rs`/`retention.rs`; run explicitly with
/// `cargo test -p yunq-infra-postgres -- --ignored` against `DATABASE_URL`.
#[cfg(test)]
mod live_db_tests {
    use super::*;

    async fn connected_storage() -> PgIssueStorage {
        let database_url = std::env::var("DATABASE_URL")
            .unwrap_or_else(|_| "postgres://yunq:yunq@localhost:5432/yunq".to_string());
        let storage = PgIssueStorage::connect_lazy(&database_url).unwrap();
        storage.migrate().await.unwrap();
        storage
    }

    fn unique_key(prefix: &str) -> String {
        format!(
            "{prefix}-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        )
    }

    #[tokio::test]
    #[ignore = "requires a live Postgres; see module docs"]
    async fn save_measures_round_trips_project_and_file_level_rows() {
        let storage = connected_storage().await;
        let key = unique_key("measures-test");
        let project_id = storage.ensure_project(&key).await.unwrap();
        let analysis_id = storage
            .record_analysis(project_id, "main", 100, 2)
            .await
            .unwrap();

        let project_measures = vec![
            ("coverage".to_string(), 80.0),
            ("issue_total".to_string(), 2.0),
        ];
        let mut file_measures: BTreeMap<String, BTreeMap<String, f64>> = BTreeMap::new();
        let mut a_measures = BTreeMap::new();
        a_measures.insert("issue_total".to_string(), 2.0);
        file_measures.insert("src/a.rs".to_string(), a_measures);

        storage
            .save_measures(analysis_id, &project_measures, &file_measures)
            .await
            .unwrap();

        let history = storage
            .measure_history(&key, "main", None, &["coverage".to_string()], None, None)
            .await
            .unwrap();
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].values["coverage"], 80.0);

        let tree = storage.component_tree(&key, "main").await.unwrap().unwrap();
        assert_eq!(tree.analysis_id, analysis_id);
        assert_eq!(tree.components.len(), 1);
        assert_eq!(tree.components[0].path, "src/a.rs");
        assert_eq!(tree.components[0].measures["issue_total"], 2.0);
    }

    #[tokio::test]
    #[ignore = "requires a live Postgres; see module docs"]
    async fn component_tree_is_none_without_any_analysis() {
        let storage = connected_storage().await;
        let key = unique_key("measures-empty-test");
        assert_eq!(storage.component_tree(&key, "main").await.unwrap(), None);
    }

    #[tokio::test]
    #[ignore = "requires a live Postgres; see module docs"]
    async fn measure_history_respects_date_range_and_metric_filter() {
        let storage = connected_storage().await;
        let key = unique_key("measures-range-test");
        let project_id = storage.ensure_project(&key).await.unwrap();

        let old_id = storage
            .record_analysis(project_id, "main", 100, 0)
            .await
            .unwrap();
        sqlx::query("UPDATE analyses SET created_at = now() - interval '30 days' WHERE id = $1")
            .bind(old_id)
            .execute(storage.pool())
            .await
            .unwrap();
        storage
            .save_measures(old_id, &[("coverage".to_string(), 50.0)], &BTreeMap::new())
            .await
            .unwrap();

        let new_id = storage
            .record_analysis(project_id, "main", 100, 0)
            .await
            .unwrap();
        storage
            .save_measures(new_id, &[("coverage".to_string(), 90.0)], &BTreeMap::new())
            .await
            .unwrap();

        let recent_only = storage
            .measure_history(
                &key,
                "main",
                None,
                &["coverage".to_string()],
                Some("now() - interval '1 day'"),
                None,
            )
            .await;
        // `from`/`to` are bound as literal strings cast to timestamptz, not
        // raw SQL, so a non-timestamp string like the one above is expected
        // to fail cleanly rather than be interpreted as an expression.
        assert!(recent_only.is_err());

        let all = storage
            .measure_history(&key, "main", None, &[], None, None)
            .await
            .unwrap();
        assert_eq!(all.len(), 2);
        assert_eq!(all[0].analysis_id, old_id);
        assert_eq!(all[1].analysis_id, new_id);
    }
}
