//! Failure diagnostics surface. ROADMAP §Phase 4 — "failure diagnostics"
//! (worker crashes, queue backlog, slow queries).
//!
//! Skeleton: the diagnostic snapshot shape and pure helpers are in place;
//! the data sources (worker heartbeats, query telemetry, queue depth
//! read) wire up in following iterations.

use serde::{Deserialize, Serialize};

/// One worker heartbeat — every worker sends one every N seconds. Stale
/// heartbeats (no update in `threshold_seconds`) are flagged as crashed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkerHeartbeat {
    pub worker_id: String,
    pub last_heartbeat_unix: u64,
    pub current_task: Option<String>,
    pub uptime_seconds: u64,
}

/// One recorded slow query — captured by query telemetry.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SlowQueryRecord {
    pub query_fingerprint: String,
    pub database: String,
    pub avg_duration_ms: u64,
    pub p99_duration_ms: u64,
    pub samples: u64,
}

/// The aggregated diagnostic snapshot — what the `/api/diagnostics`
/// endpoint returns.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct DiagnosticSnapshot {
    pub workers: Vec<WorkerHeartbeat>,
    pub crashed_workers: Vec<String>,
    pub queue_depth: usize,
    pub slowest_queries: Vec<SlowQueryRecord>,
    pub oldest_pending_task_age_seconds: Option<u64>,
}

/// Pure helper: flag workers as crashed when their last heartbeat is
/// older than `threshold_seconds`.
pub fn crashed_workers(workers: &[WorkerHeartbeat], now_unix: u64, threshold_seconds: u64) -> Vec<String> {
    workers.iter()
        .filter(|w| now_unix.saturating_sub(w.last_heartbeat_unix) > threshold_seconds)
        .map(|w| w.worker_id.clone())
        .collect()
}

/// Top-N slowest queries by p99 — sorted desc, capped at `limit`.
pub fn top_slowest(queries: &[SlowQueryRecord], limit: usize) -> Vec<SlowQueryRecord> {
    let mut sorted = queries.to_vec();
    sorted.sort_by(|a, b| b.p99_duration_ms.cmp(&a.p99_duration_ms));
    sorted.truncate(limit);
    sorted
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fresh_worker_is_not_crashed() {
        let now = 1_700_000_000u64;
        let workers = vec![WorkerHeartbeat { worker_id: "w1".to_string(), last_heartbeat_unix: now - 5, current_task: None, uptime_seconds: 100 }];
        let crashed = crashed_workers(&workers, now, 30);
        assert!(crashed.is_empty());
    }

    #[test]
    fn stale_worker_is_flagged_crashed() {
        let now = 1_700_000_000u64;
        let workers = vec![
            WorkerHeartbeat { worker_id: "w1".to_string(), last_heartbeat_unix: now - 5, current_task: None, uptime_seconds: 100 },
            WorkerHeartbeat { worker_id: "w2".to_string(), last_heartbeat_unix: now - 120, current_task: None, uptime_seconds: 200 },
        ];
        let crashed = crashed_workers(&workers, now, 30);
        assert_eq!(crashed, vec!["w2"]);
    }

    #[test]
    fn threshold_of_zero_flags_every_stale_worker() {
        let now = 1_700_000_000u64;
        let workers = vec![WorkerHeartbeat { worker_id: "w1".to_string(), last_heartbeat_unix: now - 1, current_task: None, uptime_seconds: 1 }];
        let crashed = crashed_workers(&workers, now, 0);
        assert_eq!(crashed, vec!["w1"]);
    }

    #[test]
    fn top_slowest_orders_by_p99_desc_and_caps_limit() {
        let queries = vec![
            SlowQueryRecord { query_fingerprint: "a".to_string(), database: "pg".to_string(), avg_duration_ms: 100, p99_duration_ms: 100, samples: 5 },
            SlowQueryRecord { query_fingerprint: "b".to_string(), database: "pg".to_string(), avg_duration_ms: 10, p99_duration_ms: 5_000, samples: 3 },
            SlowQueryRecord { query_fingerprint: "c".to_string(), database: "pg".to_string(), avg_duration_ms: 1, p99_duration_ms: 10, samples: 100 },
        ];
        let top = top_slowest(&queries, 2);
        assert_eq!(top.len(), 2);
        assert_eq!(top[0].query_fingerprint, "b");
        assert_eq!(top[1].query_fingerprint, "a");
    }

    #[test]
    fn top_slowest_with_limit_larger_than_input_returns_all() {
        let queries = vec![
            SlowQueryRecord { query_fingerprint: "a".to_string(), database: "pg".to_string(), avg_duration_ms: 1, p99_duration_ms: 2, samples: 1 },
        ];
        let top = top_slowest(&queries, 10);
        assert_eq!(top.len(), 1);
    }

    #[test]
    fn snapshot_default_is_empty() {
        let s = DiagnosticSnapshot::default();
        assert!(s.workers.is_empty());
        assert!(s.crashed_workers.is_empty());
        assert_eq!(s.queue_depth, 0);
        assert!(s.slowest_queries.is_empty());
        assert!(s.oldest_pending_task_age_seconds.is_none());
    }

    #[test]
    fn worker_heartbeat_round_trips_through_json() {
        let w = WorkerHeartbeat { worker_id: "w1".to_string(), last_heartbeat_unix: 1_000, current_task: Some("scan-42".to_string()), uptime_seconds: 3_600 };
        let json = serde_json::to_string(&w).unwrap();
        let restored: WorkerHeartbeat = serde_json::from_str(&json).unwrap();
        assert_eq!(w, restored);
    }
}
