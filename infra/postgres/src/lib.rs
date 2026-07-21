//! Outbound adapter: persists issues and metrics in PostgreSQL via sqlx.
//! Uses runtime-checked queries on purpose — no live database is needed at
//! build time. Implements the segregated core ports (`IssueStorage`,
//! `IssueReader`, `MetricsTracker`); consumers depend only on what they use.

use sqlx::postgres::{PgPoolOptions, PgRow};
use sqlx::{PgPool, Row};
use yunq_ast::Span;
use yunq_rules_engine::{
    Issue, IssueReader, IssueStatus, IssueStorage, IssueTransition, IssueWorkflow, Metrics,
    MetricsTracker, Resolution, RuleId, Severity, StorageError, StoredIssue, WorkflowError,
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
                "INSERT INTO issues (rule, severity, file, start_line, start_col, end_line, end_col, message, status, resolution, assignee)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)",
            )
            .bind(issue.rule().as_str())
            .bind(issue.severity().as_str())
            .bind(issue.file())
            .bind(issue.span().start_line as i32)
            .bind(issue.span().start_col as i32)
            .bind(issue.span().end_line as i32)
            .bind(issue.span().end_col as i32)
            .bind(issue.message())
            .bind(issue.status().to_string())
            .bind(issue.resolution().map(|r| r.to_string()))
            .bind(issue.assignee())
            .execute(&mut *tx)
            .await
            .map_err(storage_err)?;
        }
        tx.commit().await.map_err(storage_err)
    }
}

const ISSUE_COLUMNS: &str =
    "id, rule, severity, file, start_line, start_col, end_line, end_col, message, status, resolution, assignee";

/// Rehydrates one row through the strict domain constructors; corrupt rows
/// surface as errors, never as invalid domain values.
fn issue_from_row(row: &PgRow) -> Result<StoredIssue, StorageError> {
    let id: i64 = row.try_get("id").map_err(storage_err)?;
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
    let status_raw: String = row.try_get("status").map_err(storage_err)?;
    let status = IssueStatus::parse(&status_raw)
        .ok_or_else(|| StorageError(format!("invalid status {status_raw:?}")))?;
    let resolution = row
        .try_get::<Option<String>, _>("resolution")
        .map_err(storage_err)?
        .map(|raw| {
            Resolution::parse(&raw).ok_or_else(|| StorageError(format!("invalid resolution {raw:?}")))
        })
        .transpose()?;
    let issue = Issue::restore(
        rule,
        severity,
        row.try_get::<String, _>("message").map_err(storage_err)?,
        row.try_get::<String, _>("file").map_err(storage_err)?,
        span,
        status,
        resolution,
        row.try_get::<Option<String>, _>("assignee").map_err(storage_err)?,
    )
    .map_err(storage_err)?;
    Ok(StoredIssue { id, issue })
}

impl IssueReader for PgIssueStorage {
    async fn recent_issues(&self, limit: usize) -> Result<Vec<StoredIssue>, StorageError> {
        let rows = sqlx::query(&format!(
            "SELECT {ISSUE_COLUMNS} FROM issues ORDER BY id DESC LIMIT $1"
        ))
        .bind(limit as i64)
        .fetch_all(&self.pool)
        .await
        .map_err(storage_err)?;

        rows.iter().map(issue_from_row).collect()
    }
}

impl PgIssueStorage {
    async fn fetch_issue(&self, issue_id: i64) -> Result<StoredIssue, WorkflowError> {
        let row = sqlx::query(&format!("SELECT {ISSUE_COLUMNS} FROM issues WHERE id = $1"))
            .bind(issue_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(storage_err)?
            .ok_or(WorkflowError::NotFound(issue_id))?;
        issue_from_row(&row).map_err(|e| WorkflowError::Corrupt(issue_id, e.to_string()))
    }

    async fn store_workflow_state(&self, stored: &StoredIssue) -> Result<(), WorkflowError> {
        sqlx::query("UPDATE issues SET status = $1, resolution = $2, assignee = $3 WHERE id = $4")
            .bind(stored.issue.status().to_string())
            .bind(stored.issue.resolution().map(|r| r.to_string()))
            .bind(stored.issue.assignee())
            .bind(stored.id)
            .execute(&self.pool)
            .await
            .map_err(storage_err)?;
        Ok(())
    }
}

impl IssueWorkflow for PgIssueStorage {
    async fn apply_transition(
        &self,
        issue_id: i64,
        transition: IssueTransition,
    ) -> Result<StoredIssue, WorkflowError> {
        let mut stored = self.fetch_issue(issue_id).await?;
        stored.issue.apply(transition)?;
        self.store_workflow_state(&stored).await?;
        Ok(stored)
    }

    async fn set_assignee(
        &self,
        issue_id: i64,
        assignee: Option<String>,
    ) -> Result<StoredIssue, WorkflowError> {
        let mut stored = self.fetch_issue(issue_id).await?;
        match assignee {
            Some(user) => stored.issue.assign(user),
            None => stored.issue.unassign(),
        }
        self.store_workflow_state(&stored).await?;
        Ok(stored)
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
