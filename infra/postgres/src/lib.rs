//! Outbound adapter: persists issues and metrics in PostgreSQL via sqlx.
//! Uses runtime-checked queries on purpose — no live database is needed at
//! build time. Implements the segregated core ports (`IssueStorage`,
//! `IssueReader`, `MetricsTracker`); consumers depend only on what they use.

use sqlx::postgres::PgPoolOptions;
use sqlx::{PgPool, Row};
use yunq_ast::Span;
use yunq_rules_engine::{
    Issue, IssueReader, IssueStorage, Metrics, MetricsTracker, RuleId, Severity, StorageError,
};

#[derive(Clone)]
pub struct PgIssueStorage {
    pool: PgPool,
}

impl PgIssueStorage {
    /// Creates the adapter without touching the network; connections are
    /// established on first use.
    pub fn connect_lazy(database_url: &str) -> Result<Self, StorageError> {
        let pool = PgPoolOptions::new()
            .max_connections(5)
            .connect_lazy(database_url)
            .map_err(storage_err)?;
        Ok(Self { pool })
    }

    /// Applies the embedded migrations (compiled in at build time).
    pub async fn migrate(&self) -> Result<(), StorageError> {
        sqlx::migrate!("./migrations").run(&self.pool).await.map_err(storage_err)
    }
}

fn storage_err(e: impl std::fmt::Display) -> StorageError {
    StorageError(e.to_string())
}

impl IssueStorage for PgIssueStorage {
    async fn save_issues(&self, issues: &[Issue]) -> Result<(), StorageError> {
        let mut tx = self.pool.begin().await.map_err(storage_err)?;
        for issue in issues {
            sqlx::query(
                "INSERT INTO issues (rule, severity, file, start_line, start_col, end_line, end_col, message)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
            )
            .bind(issue.rule().as_str())
            .bind(issue.severity().as_str())
            .bind(issue.file())
            .bind(issue.span().start_line as i32)
            .bind(issue.span().start_col as i32)
            .bind(issue.span().end_line as i32)
            .bind(issue.span().end_col as i32)
            .bind(issue.message())
            .execute(&mut *tx)
            .await
            .map_err(storage_err)?;
        }
        tx.commit().await.map_err(storage_err)
    }
}

impl IssueReader for PgIssueStorage {
    async fn recent_issues(&self, limit: usize) -> Result<Vec<Issue>, StorageError> {
        let rows = sqlx::query(
            "SELECT rule, severity, file, start_line, start_col, end_line, end_col, message
             FROM issues ORDER BY id DESC LIMIT $1",
        )
        .bind(limit as i64)
        .fetch_all(&self.pool)
        .await
        .map_err(storage_err)?;

        rows.into_iter()
            .map(|row| {
                // Stored data is translated back through the strict domain
                // constructors; corrupt rows surface as errors, never as
                // invalid domain values.
                let rule = RuleId::new(row.try_get::<String, _>("rule").map_err(storage_err)?.as_str())
                    .map_err(storage_err)?;
                let severity_raw: String = row.try_get("severity").map_err(storage_err)?;
                let severity = Severity::parse(&severity_raw)
                    .ok_or_else(|| StorageError(format!("invalid severity {severity_raw:?}")))?;
                let span = Span::new(
                    row.try_get::<i32, _>("start_line").map_err(storage_err)? as u32,
                    row.try_get::<i32, _>("start_col").map_err(storage_err)? as u32,
                    row.try_get::<i32, _>("end_line").map_err(storage_err)? as u32,
                    row.try_get::<i32, _>("end_col").map_err(storage_err)? as u32,
                );
                Ok(Issue::new(
                    rule,
                    severity,
                    row.try_get::<String, _>("message").map_err(storage_err)?,
                    row.try_get::<String, _>("file").map_err(storage_err)?,
                    span,
                ))
            })
            .collect()
    }
}

impl MetricsTracker for PgIssueStorage {
    async fn record(&self, metrics: &Metrics) -> Result<(), StorageError> {
        sqlx::query(
            "INSERT INTO scan_metrics (files_scanned, files_skipped, parse_failures, lines_of_code, issue_total)
             VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(metrics.files_scanned() as i32)
        .bind(metrics.files_skipped() as i32)
        .bind(metrics.parse_failures() as i32)
        .bind(metrics.lines_of_code() as i64)
        .bind(metrics.issue_total() as i32)
        .execute(&self.pool)
        .await
        .map_err(storage_err)?;
        Ok(())
    }
}
