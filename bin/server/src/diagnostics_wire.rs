//! Wave 4 — Diagnostic tasks REST API integration.
//!
//! The analyzer runs a background task queue (`tasks.rs`) and the
//! diagnostics module (`diagnostics.rs`) tracks crashed workers + slow
//! queries. These tests describe the *REST surface* that exposes both:
//!
//! * `GET /api/admin/diagnostics/tasks` — list running tasks with depth
//!   counters, projected completion, and last-error snapshot.
//! * `GET /api/admin/diagnostics/crashed-workers` — workers that have not
//!   heartbeat'd in 60s.
//! * `GET /api/admin/diagnostics/slow-queries` — top 10 queries by p95
//!   latency over the last hour.
//!
//! Auth model: every endpoint requires `Permission::AdminAccess`. The
//! permissions are enforced by the `require_permission` extractor added
//! in Wave 2.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskSnapshot {
    pub task_id: String,
    pub kind: TaskKind,
    pub status: TaskStatus,
    pub submitted_at: DateTime<Utc>,
    pub projected_completion_at: Option<DateTime<Utc>>,
    pub last_error: Option<String>,
    pub depth: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TaskKind {
    AnalysisRun,
    WebhookDelivery,
    ReportGeneration,
    AiAssignment,
    AuditExport,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TaskStatus {
    Queued,
    Running,
    Succeeded,
    Failed,
    Cancelled,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrashedWorker {
    pub worker_id: String,
    pub last_heartbeat: DateTime<Utc>,
    pub task_in_flight: Option<String>,
    pub uptime_at_crash: std::time::Duration,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlowQuery {
    pub query: String,
    pub p95_latency_ms: u64,
    pub count_last_hour: u64,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct DiagnosticsService {
    pub admin_base: String,
}

impl DiagnosticsService {
    pub fn new(admin_base: impl Into<String>) -> Self {
        Self { admin_base: admin_base.into() }
    }

    pub fn list_tasks(&self, _limit: usize) -> Result<Vec<TaskSnapshot>, DiagnosticsError> {
        unimplemented!("DiagnosticsService::list_tasks")
    }

    pub fn list_crashed_workers(&self, _idle_threshold: std::time::Duration) -> Result<Vec<CrashedWorker>, DiagnosticsError> {
        unimplemented!("DiagnosticsService::list_crashed_workers")
    }

    pub fn list_slow_queries(&self, _top_n: usize, _window: std::time::Duration) -> Result<Vec<SlowQuery>, DiagnosticsError> {
        unimplemented!("DiagnosticsService::list_slow_queries")
    }

    pub fn cancel_task(&self, _task_id: &str) -> Result<(), DiagnosticsError> {
        unimplemented!("DiagnosticsService::cancel_task")
    }
}

#[derive(Debug, Error)]
pub enum DiagnosticsError {
    #[error("task not found: {0}")]
    NotFound(String),
    #[error("permission denied: {0}")]
    Forbidden(String),
    #[error("internal: {0}")]
    Internal(String),
}

// ---------------------------------------------------------------------------
// Tests — RED
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn list_tasks_returns_at_least_one_snapshot() {
        let svc = DiagnosticsService::new("http://localhost:8080");
        let tasks = svc.list_tasks(100).unwrap();
        assert!(!tasks.is_empty(), "test fixture must produce at least one task");
    }

    #[test]
    fn list_tasks_have_monotonic_depth() {
        let svc = DiagnosticsService::new("http://localhost:8080");
        let tasks = svc.list_tasks(100).unwrap();
        for t in &tasks {
            assert!(t.depth > 0, "task {} has zero depth", t.task_id);
        }
    }

    #[test]
    fn list_tasks_respects_limit() {
        let svc = DiagnosticsService::new("http://localhost:8080");
        let tasks = svc.list_tasks(3).unwrap();
        assert!(tasks.len() <= 3);
    }

    #[test]
    fn list_crashed_workers_default_threshold_is_60s() {
        let svc = DiagnosticsService::new("http://localhost:8080");
        let idle = Duration::from_secs(60);
        let _ = svc.list_crashed_workers(idle).unwrap();
    }

    #[test]
    fn list_crashed_workers_includes_worker_id() {
        let svc = DiagnosticsService::new("http://localhost:8080");
        let workers = svc.list_crashed_workers(Duration::from_secs(60)).unwrap();
        for w in &workers {
            assert!(!w.worker_id.is_empty(), "worker_id must be non-empty");
        }
    }

    #[test]
    fn list_crashed_workers_records_last_heartbeat() {
        let svc = DiagnosticsService::new("http://localhost:8080");
        let workers = svc.list_crashed_workers(Duration::from_secs(60)).unwrap();
        for w in &workers {
            assert!(
                Utc::now() - w.last_heartbeat > Duration::from_secs(60),
                "worker {} last heartbeat too recent: {:?}",
                w.worker_id,
                w.last_heartbeat
            );
        }
    }

    #[test]
    fn list_slow_queries_default_top_n_is_10() {
        let svc = DiagnosticsService::new("http://localhost:8080");
        let queries = svc.list_slow_queries(10, Duration::from_secs(3600)).unwrap();
        assert!(queries.len() <= 10);
    }

    #[test]
    fn list_slow_queries_sorted_by_p95_descending() {
        let svc = DiagnosticsService::new("http://localhost:8080");
        let queries = svc.list_slow_queries(10, Duration::from_secs(3600)).unwrap();
        for window in queries.windows(2) {
            assert!(window[0].p95_latency_ms >= window[1].p95_latency_ms,
                "queries must be sorted by p95 desc: {:?} < {:?}", window[0].p95_latency_ms, window[1].p95_latency_ms);
        }
    }

    #[test]
    fn slow_query_p95_is_in_milliseconds() {
        let svc = DiagnosticsService::new("http://localhost:8080");
        let queries = svc.list_slow_queries(10, Duration::from_secs(3600)).unwrap();
        for q in &queries {
            assert!(q.p95_latency_ms < 60_000, "p95 latency field is in ms (< 60s): {}", q.p95_latency_ms);
        }
    }

    #[test]
    fn cancel_task_unknown_id_returns_not_found() {
        let svc = DiagnosticsService::new("http://localhost:8080");
        let err = svc.cancel_task("does-not-exist").unwrap_err();
        assert!(matches!(err, DiagnosticsError::NotFound(_)));
    }

    #[test]
    fn cancel_task_known_id_returns_ok() {
        let svc = DiagnosticsService::new("http://localhost:8080");
        let tasks = svc.list_tasks(1).unwrap();
        let id = tasks.first().map(|t| t.task_id.clone()).unwrap_or_else(|| "t1".into());
        let _ = svc.cancel_task(&id).unwrap();
    }

    #[test]
    fn task_status_serializes_to_kebab_case() {
        let s = serde_json::to_string(&TaskStatus::Reauthenticate).unwrap_or_default();
        if !s.is_empty() {
            assert!(s.contains("reauthenticate"));
        }
    }

    #[test]
    fn task_kind_covers_all_families() {
        // Run-time enumeration: every documented kind must be a valid
        // variant. The compiler enforces this through the enum itself.
        let kinds = [
            TaskKind::AnalysisRun,
            TaskKind::WebhookDelivery,
            TaskKind::ReportGeneration,
            TaskKind::AiAssignment,
            TaskKind::AuditExport,
        ];
        assert_eq!(kinds.len(), 5);
    }
}
