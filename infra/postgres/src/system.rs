//! Outbound adapter: the cheap operational snapshot behind
//! `GET /api/system/info` — Postgres reachability/version plus counters
//! that are already indexed, so nothing here scans a table.

use sqlx::Row;

use crate::PgIssueStorage;

/// Postgres reachability plus a handful of cheap counters. Every field
/// fails open (defaults reported instead of an error) — this endpoint is a
/// diagnostic, not something that should 500 because a count query hiccups.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct SystemSnapshot {
    pub database_connected: bool,
    pub postgres_version: Option<String>,
    pub issues_total: i64,
    pub hotspots_total: i64,
    pub pending_scan_jobs: i64,
}

impl PgIssueStorage {
    pub async fn system_snapshot(&self) -> SystemSnapshot {
        let postgres_version = sqlx::query("SELECT version() AS v")
            .fetch_one(&self.pool)
            .await
            .ok()
            .and_then(|row| row.try_get::<String, _>("v").ok());
        let database_connected = postgres_version.is_some();

        let issues_total = self.scalar_count("SELECT COUNT(*) AS n FROM issues").await;
        let hotspots_total = self
            .scalar_count("SELECT COUNT(*) AS n FROM hotspots")
            .await;
        let pending_scan_jobs = self
            .scalar_count("SELECT COUNT(*) AS n FROM scan_jobs WHERE status = 'pending'")
            .await;

        SystemSnapshot {
            database_connected,
            postgres_version,
            issues_total,
            hotspots_total,
            pending_scan_jobs,
        }
    }

    async fn scalar_count(&self, sql: &str) -> i64 {
        sqlx::query(sql)
            .fetch_one(&self.pool)
            .await
            .ok()
            .and_then(|row| row.try_get::<i64, _>("n").ok())
            .unwrap_or(0)
    }
}
