//! Outbound adapter: persists issues and metrics in PostgreSQL via sqlx.
//! Uses runtime-checked queries on purpose — no live database is needed at
//! build time. Implements the segregated core ports (`IssueStorage`,
//! `IssueReader`, `MetricsTracker`); consumers depend only on what they use.

use sqlx::postgres::{PgPoolOptions, PgRow, Postgres};
use sqlx::{PgPool, QueryBuilder, Row};
use yunq_ast::Span;
use yunq_rules_engine::{
    BulkOutcome, ChangelogAction, ChangelogEntry, Hotspot, HotspotReader, HotspotReview,
    HotspotStatus, HotspotStorage, Issue, IssueBulkWorkflow, IssueChangelogReader,
    IssueFacetReader, IssueFacets, IssueQuery, IssueReader, IssueStatus, IssueStorage,
    IssueTransition, IssueWorkflow, Metrics, MetricsTracker, Page, Resolution, RuleId, Severity,
    StorageError, StoredHotspot, StoredIssue, WorkflowError,
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

/// Appends the query's conjunctive filters to a `WHERE 1=1` builder.
enum FacetSkip {
    None,
    Severity,
    Status,
    Rule,
}

fn push_issue_filters<'a>(builder: &mut QueryBuilder<'a, Postgres>, query: &'a IssueQuery) {
    push_issue_filters_skip(builder, query, &FacetSkip::None);
}

/// Same filters as [`push_issue_filters`], optionally dropping one
/// dimension's own condition — used to compute facet counts that answer
/// "what if I also picked this value" rather than collapsing to it.
fn push_issue_filters_skip<'a>(
    builder: &mut QueryBuilder<'a, Postgres>,
    query: &'a IssueQuery,
    skip: &FacetSkip,
) {
    if !matches!(skip, FacetSkip::Severity)
        && let Some(severity) = query.severity
    {
        builder.push(" AND severity = ").push_bind(severity.as_str().to_string());
    }
    if !matches!(skip, FacetSkip::Status)
        && let Some(status) = query.status
    {
        builder.push(" AND status = ").push_bind(status.to_string());
    }
    if !matches!(skip, FacetSkip::Rule)
        && let Some(rule) = &query.rule
    {
        builder.push(" AND rule = ").push_bind(rule.as_str());
    }
    if let Some(file) = &query.file {
        builder.push(" AND file LIKE ").push_bind(format!("%{file}%"));
    }
    if let Some(assignee) = &query.assignee {
        builder.push(" AND assignee = ").push_bind(assignee.as_str());
    }
}

impl IssueReader for PgIssueStorage {
    async fn search_issues(&self, query: &IssueQuery) -> Result<Page<StoredIssue>, StorageError> {
        let mut count = QueryBuilder::<Postgres>::new("SELECT COUNT(*) FROM issues WHERE 1=1");
        push_issue_filters(&mut count, query);
        let total: i64 =
            count.build_query_scalar().fetch_one(&self.pool).await.map_err(storage_err)?;

        let mut select = QueryBuilder::<Postgres>::new(format!(
            "SELECT {ISSUE_COLUMNS} FROM issues WHERE 1=1"
        ));
        push_issue_filters(&mut select, query);
        select
            .push(" ORDER BY id DESC LIMIT ")
            .push_bind(query.normalized_page_size() as i64)
            .push(" OFFSET ")
            .push_bind(query.offset() as i64);
        let rows = select.build().fetch_all(&self.pool).await.map_err(storage_err)?;

        Ok(Page {
            items: rows.iter().map(issue_from_row).collect::<Result<_, _>>()?,
            page: query.normalized_page(),
            page_size: query.normalized_page_size(),
            total: total as usize,
        })
    }
}

impl IssueFacetReader for PgIssueStorage {
    async fn facets(&self, query: &IssueQuery) -> Result<IssueFacets, StorageError> {
        let mut by_severity_q = QueryBuilder::<Postgres>::new(
            "SELECT severity, COUNT(*) AS n FROM issues WHERE 1=1",
        );
        push_issue_filters_skip(&mut by_severity_q, query, &FacetSkip::Severity);
        by_severity_q.push(" GROUP BY severity");
        let severity_rows =
            by_severity_q.build().fetch_all(&self.pool).await.map_err(storage_err)?;
        let mut by_severity = std::collections::BTreeMap::new();
        for row in &severity_rows {
            let raw: String = row.try_get("severity").map_err(storage_err)?;
            let severity = Severity::parse(&raw)
                .ok_or_else(|| StorageError(format!("invalid severity {raw:?}")))?;
            let count: i64 = row.try_get("n").map_err(storage_err)?;
            by_severity.insert(severity, count as usize);
        }

        let mut by_status_q =
            QueryBuilder::<Postgres>::new("SELECT status, COUNT(*) AS n FROM issues WHERE 1=1");
        push_issue_filters_skip(&mut by_status_q, query, &FacetSkip::Status);
        by_status_q.push(" GROUP BY status");
        let status_rows = by_status_q.build().fetch_all(&self.pool).await.map_err(storage_err)?;
        let mut by_status = Vec::new();
        for row in &status_rows {
            let raw: String = row.try_get("status").map_err(storage_err)?;
            let status = IssueStatus::parse(&raw)
                .ok_or_else(|| StorageError(format!("invalid status {raw:?}")))?;
            let count: i64 = row.try_get("n").map_err(storage_err)?;
            by_status.push((status, count as usize));
        }

        let mut by_rule_q =
            QueryBuilder::<Postgres>::new("SELECT rule, COUNT(*) AS n FROM issues WHERE 1=1");
        push_issue_filters_skip(&mut by_rule_q, query, &FacetSkip::Rule);
        by_rule_q.push(" GROUP BY rule");
        let rule_rows = by_rule_q.build().fetch_all(&self.pool).await.map_err(storage_err)?;
        let mut by_rule = Vec::new();
        for row in &rule_rows {
            let raw: String = row.try_get("rule").map_err(storage_err)?;
            let rule = RuleId::new(&raw).map_err(storage_err)?;
            let count: i64 = row.try_get("n").map_err(storage_err)?;
            by_rule.push((rule, count as usize));
        }

        Ok(IssueFacets { by_severity, by_status, by_rule })
    }
}

fn hotspot_from_row(row: &PgRow) -> Result<StoredHotspot, StorageError> {
    let id: i64 = row.try_get("id").map_err(storage_err)?;
    let rule = RuleId::new(row.try_get::<String, _>("rule").map_err(storage_err)?.as_str())
        .map_err(storage_err)?;
    let status_raw: String = row.try_get("status").map_err(storage_err)?;
    let status = HotspotStatus::parse(&status_raw)
        .ok_or_else(|| StorageError(format!("invalid hotspot status {status_raw:?}")))?;
    let span = Span::new(
        row.try_get::<i32, _>("start_line").map_err(storage_err)? as u32,
        row.try_get::<i32, _>("start_col").map_err(storage_err)? as u32,
        row.try_get::<i32, _>("end_line").map_err(storage_err)? as u32,
        row.try_get::<i32, _>("end_col").map_err(storage_err)? as u32,
    );
    Ok(StoredHotspot {
        id,
        hotspot: Hotspot::restore(
            rule,
            row.try_get::<String, _>("message").map_err(storage_err)?,
            row.try_get::<String, _>("file").map_err(storage_err)?,
            span,
            status,
        ),
    })
}

impl HotspotStorage for PgIssueStorage {
    async fn save_hotspots(&self, hotspots: &[Hotspot]) -> Result<(), StorageError> {
        let mut tx = self.pool.begin().await.map_err(storage_err)?;
        for hotspot in hotspots {
            sqlx::query(
                "INSERT INTO hotspots (rule, message, file, start_line, start_col, end_line, end_col, status)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
            )
            .bind(hotspot.rule().as_str())
            .bind(hotspot.message())
            .bind(hotspot.file())
            .bind(hotspot.span().start_line as i32)
            .bind(hotspot.span().start_col as i32)
            .bind(hotspot.span().end_line as i32)
            .bind(hotspot.span().end_col as i32)
            .bind(hotspot.status().to_string())
            .execute(&mut *tx)
            .await
            .map_err(storage_err)?;
        }
        tx.commit().await.map_err(storage_err)
    }
}

impl HotspotReader for PgIssueStorage {
    async fn recent_hotspots(&self, limit: usize) -> Result<Vec<StoredHotspot>, StorageError> {
        let rows = sqlx::query(
            "SELECT id, rule, message, file, start_line, start_col, end_line, end_col, status
             FROM hotspots ORDER BY id DESC LIMIT $1",
        )
        .bind(limit as i64)
        .fetch_all(&self.pool)
        .await
        .map_err(storage_err)?;
        rows.iter().map(hotspot_from_row).collect()
    }
}

impl HotspotReview for PgIssueStorage {
    async fn review_hotspot(
        &self,
        hotspot_id: i64,
        status: HotspotStatus,
    ) -> Result<StoredHotspot, WorkflowError> {
        let row = sqlx::query(
            "UPDATE hotspots SET status = $1 WHERE id = $2
             RETURNING id, rule, message, file, start_line, start_col, end_line, end_col, status",
        )
        .bind(status.to_string())
        .bind(hotspot_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(storage_err)?
        .ok_or(WorkflowError::NotFound(hotspot_id))?;
        hotspot_from_row(&row).map_err(|e| WorkflowError::Corrupt(hotspot_id, e.to_string()))
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

    async fn record_transition(
        &self,
        issue_id: i64,
        from: IssueStatus,
        transition: IssueTransition,
    ) -> Result<(), WorkflowError> {
        let (name, resolution) = match transition {
            IssueTransition::Confirm => ("confirm", None),
            IssueTransition::Reopen => ("reopen", None),
            IssueTransition::Close => ("close", None),
            IssueTransition::Resolve(r) => ("resolve", Some(r.to_string())),
        };
        sqlx::query(
            "INSERT INTO issue_changelog (issue_id, action, from_status, transition, resolution)
             VALUES ($1, 'transitioned', $2, $3, $4)",
        )
        .bind(issue_id)
        .bind(from.to_string())
        .bind(name)
        .bind(resolution)
        .execute(&self.pool)
        .await
        .map_err(storage_err)?;
        Ok(())
    }

    async fn record_assignment(
        &self,
        issue_id: i64,
        assignee: Option<&str>,
    ) -> Result<(), WorkflowError> {
        sqlx::query(
            "INSERT INTO issue_changelog (issue_id, action, assignee) VALUES ($1, 'assigned', $2)",
        )
        .bind(issue_id)
        .bind(assignee)
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
        let from = stored.issue.status();
        stored.issue.apply(transition)?;
        self.store_workflow_state(&stored).await?;
        self.record_transition(issue_id, from, transition).await?;
        Ok(stored)
    }

    async fn set_assignee(
        &self,
        issue_id: i64,
        assignee: Option<String>,
    ) -> Result<StoredIssue, WorkflowError> {
        let mut stored = self.fetch_issue(issue_id).await?;
        match &assignee {
            Some(user) => stored.issue.assign(user.clone()),
            None => stored.issue.unassign(),
        }
        self.store_workflow_state(&stored).await?;
        self.record_assignment(issue_id, assignee.as_deref()).await?;
        Ok(stored)
    }
}

impl IssueBulkWorkflow for PgIssueStorage {
    async fn bulk_transition(
        &self,
        issue_ids: &[i64],
        transition: IssueTransition,
    ) -> Result<Vec<BulkOutcome>, StorageError> {
        let mut outcomes = Vec::with_capacity(issue_ids.len());
        for &issue_id in issue_ids {
            match IssueWorkflow::apply_transition(self, issue_id, transition).await {
                Ok(stored) => outcomes.push(BulkOutcome::Applied(stored)),
                Err(e) => outcomes.push(BulkOutcome::Failed { issue_id, reason: e.to_string() }),
            }
        }
        Ok(outcomes)
    }
}

impl IssueChangelogReader for PgIssueStorage {
    async fn changelog(&self, issue_id: i64) -> Result<Vec<ChangelogEntry>, StorageError> {
        let rows = sqlx::query(
            "SELECT action, from_status, transition, resolution, assignee,
                    to_char(at, 'YYYY-MM-DD\"T\"HH24:MI:SS.USZ') AS at
             FROM issue_changelog WHERE issue_id = $1 ORDER BY id ASC",
        )
        .bind(issue_id)
        .fetch_all(&self.pool)
        .await
        .map_err(storage_err)?;

        rows.iter()
            .map(|row| {
                let action_kind: String = row.try_get("action").map_err(storage_err)?;
                let at: String = row.try_get("at").map_err(storage_err)?;
                let action = match action_kind.as_str() {
                    "transitioned" => {
                        let from_raw: String = row.try_get("from_status").map_err(storage_err)?;
                        let from = IssueStatus::parse(&from_raw)
                            .ok_or_else(|| StorageError(format!("invalid status {from_raw:?}")))?;
                        let transition_name: String =
                            row.try_get("transition").map_err(storage_err)?;
                        let transition = match transition_name.as_str() {
                            "confirm" => IssueTransition::Confirm,
                            "reopen" => IssueTransition::Reopen,
                            "close" => IssueTransition::Close,
                            "resolve" => {
                                let raw: String =
                                    row.try_get("resolution").map_err(storage_err)?;
                                let resolution = Resolution::parse(&raw).ok_or_else(|| {
                                    StorageError(format!("invalid resolution {raw:?}"))
                                })?;
                                IssueTransition::Resolve(resolution)
                            }
                            other => {
                                return Err(StorageError(format!("invalid transition {other:?}")));
                            }
                        };
                        ChangelogAction::Transitioned { from, transition }
                    }
                    "assigned" => ChangelogAction::Assigned {
                        assignee: row.try_get("assignee").map_err(storage_err)?,
                    },
                    other => return Err(StorageError(format!("invalid changelog action {other:?}"))),
                };
                Ok(ChangelogEntry { issue_id, action, at })
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
