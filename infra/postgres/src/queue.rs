//! Outbound adapter: scan-job queue backed by the same Postgres database as
//! issue storage — no external broker. Producers `INSERT` and `NOTIFY`;
//! consumers claim work with `UPDATE ... FOR UPDATE SKIP LOCKED` (so multiple
//! workers never grab the same row) and `LISTEN` for near-instant wakeup,
//! falling back to a periodic poll in case a notification is missed.
//!
//! Fase 4 (issue #30) added failure diagnostics: every claim increments
//! `attempts`; a handler failure records `last_error` and either releases
//! the job back to `pending` (attempts left) or dead-letters it to a
//! terminal `dead` status (retry budget exhausted) instead of retrying
//! forever with no trace. `queue_status` exposes the aggregate for the
//! task queue status API.

use std::future::Future;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use sqlx::postgres::PgListener;
use sqlx::{PgPool, Row};
use yunq_rules_engine::{JobQueue, QueueError, ScanJob};

use crate::PgIssueStorage;

const NOTIFY_CHANNEL: &str = "yunq_scan_jobs";
const POLL_FALLBACK: Duration = Duration::from_secs(5);
/// A job that has failed this many times is dead-lettered instead of
/// released for another retry.
const DEFAULT_MAX_ATTEMPTS: i32 = 5;
/// How many dead-lettered/failing jobs `queue_status` surfaces for
/// diagnosis, newest first.
const RECENT_FAILURES_LIMIT: i64 = 20;

fn queue_err(e: impl std::fmt::Display) -> QueueError {
    QueueError(e.to_string())
}

impl JobQueue for PgIssueStorage {
    async fn enqueue_scan(&self, job: ScanJob) -> Result<(), QueueError> {
        sqlx::query("INSERT INTO scan_jobs (project, path) VALUES ($1, $2)")
            .bind(job.project())
            .bind(job.path())
            .execute(self.pool())
            .await
            .map_err(queue_err)?;
        sqlx::query("SELECT pg_notify($1, '')")
            .bind(NOTIFY_CHANNEL)
            .execute(self.pool())
            .await
            .map_err(queue_err)?;
        Ok(())
    }
}

/// Long-polling consumer. Successfully handled jobs are deleted from the
/// table; handler failures release the row back to `pending` for retry.
pub struct PgJobConsumer {
    pool: PgPool,
}

impl PgJobConsumer {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn listen<F, Fut>(&self, mut handle: F) -> Result<(), QueueError>
    where
        F: FnMut(ScanJob) -> Fut,
        Fut: Future<Output = Result<(), QueueError>>,
    {
        let mut listener =
            PgListener::connect_with(&self.pool).await.map_err(queue_err)?;
        listener.listen(NOTIFY_CHANNEL).await.map_err(queue_err)?;

        loop {
            while let Some((id, job, attempts)) = self.claim_one().await? {
                match handle(job).await {
                    Ok(()) => self.delete(id).await?,
                    Err(e) => self.fail(id, attempts, &e.0).await?,
                }
            }
            // Either a NOTIFY wakes us immediately, or the fallback timeout
            // re-checks the table (covers jobs enqueued before this listener
            // connected, or a notification lost to a connection hiccup).
            let _ = tokio::time::timeout(POLL_FALLBACK, listener.recv()).await;
        }
    }

    /// Claims the oldest pending job (if any), marking it `processing` and
    /// bumping `attempts` — the count includes this claim, so a job handled
    /// successfully on its first try reports `attempts == 1`.
    async fn claim_one(&self) -> Result<Option<(i64, ScanJob, i32)>, QueueError> {
        let row = sqlx::query(
            "UPDATE scan_jobs SET status = 'processing', attempts = attempts + 1, updated_at = now()
             WHERE id = (
                 SELECT id FROM scan_jobs
                 WHERE status = 'pending'
                 ORDER BY id ASC
                 FOR UPDATE SKIP LOCKED
                 LIMIT 1
             )
             RETURNING id, project, path, attempts",
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(queue_err)?;

        let Some(row) = row else {
            return Ok(None);
        };
        let id: i64 = row.try_get("id").map_err(queue_err)?;
        let project: String = row.try_get("project").map_err(queue_err)?;
        let path: String = row.try_get("path").map_err(queue_err)?;
        let attempts: i32 = row.try_get("attempts").map_err(queue_err)?;
        let job = ScanJob::new(project, path).map_err(queue_err)?;
        Ok(Some((id, job, attempts)))
    }

    async fn delete(&self, id: i64) -> Result<(), QueueError> {
        sqlx::query("DELETE FROM scan_jobs WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(queue_err)?;
        Ok(())
    }

    /// Records `error` and either releases the job back to `pending` for
    /// another attempt, or — once `attempts` reaches `DEFAULT_MAX_ATTEMPTS`
    /// — dead-letters it so it stops being retried and shows up in
    /// `queue_status`'s failure diagnostics instead.
    async fn fail(&self, id: i64, attempts: i32, error: &str) -> Result<(), QueueError> {
        let status = if attempts >= DEFAULT_MAX_ATTEMPTS { "dead" } else { "pending" };
        sqlx::query(
            "UPDATE scan_jobs SET status = $1, last_error = $2, updated_at = now() WHERE id = $3",
        )
        .bind(status)
        .bind(error)
        .bind(id)
        .execute(&self.pool)
        .await
        .map_err(queue_err)?;
        Ok(())
    }
}

/// Aggregate queue depth by status, plus the jobs most useful for
/// diagnosing why analysis isn't completing — the shape behind
/// `GET /api/admin/queue/status`.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct QueueStatus {
    pub pending: i64,
    pub processing: i64,
    pub dead: i64,
    /// Seconds since the oldest still-pending job was created, if any.
    pub oldest_pending_age_seconds: Option<i64>,
    pub recent_failures: Vec<FailedJob>,
}

/// One job that has failed at least once — dead-lettered or still eligible
/// for retry — newest failure first.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct FailedJob {
    pub id: i64,
    pub project: String,
    pub path: String,
    pub status: String,
    pub attempts: i32,
    pub last_error: Option<String>,
    /// RFC3339 timestamp of the last status change.
    pub updated_at: String,
}

impl PgIssueStorage {
    /// Reads the current scan-job queue depth by status plus the most
    /// recent failures, for the task queue status / failure-diagnostics
    /// API. A plain read — no locking, no claim.
    pub async fn queue_status(&self) -> Result<QueueStatus, QueueError> {
        let counts = sqlx::query(
            "SELECT status, COUNT(*) AS n FROM scan_jobs
             WHERE status IN ('pending', 'processing', 'dead')
             GROUP BY status",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(queue_err)?;

        let mut status = QueueStatus::default();
        for row in counts {
            let name: String = row.try_get("status").map_err(queue_err)?;
            let n: i64 = row.try_get("n").map_err(queue_err)?;
            match name.as_str() {
                "pending" => status.pending = n,
                "processing" => status.processing = n,
                "dead" => status.dead = n,
                _ => {}
            }
        }

        status.oldest_pending_age_seconds = sqlx::query(
            "SELECT EXTRACT(EPOCH FROM (now() - MIN(created_at)))::BIGINT AS age
             FROM scan_jobs WHERE status = 'pending'",
        )
        .fetch_one(&self.pool)
        .await
        .map_err(queue_err)?
        .try_get("age")
        .map_err(queue_err)?;

        let failure_rows = sqlx::query(
            "SELECT id, project, path, status, attempts,
                    last_error,
                    to_char(updated_at, 'YYYY-MM-DD\"T\"HH24:MI:SS.USZ') AS updated_at
             FROM scan_jobs
             WHERE last_error IS NOT NULL
             ORDER BY updated_at DESC
             LIMIT $1",
        )
        .bind(RECENT_FAILURES_LIMIT)
        .fetch_all(&self.pool)
        .await
        .map_err(queue_err)?;

        status.recent_failures = failure_rows
            .iter()
            .map(|row| {
                Ok(FailedJob {
                    id: row.try_get("id").map_err(queue_err)?,
                    project: row.try_get("project").map_err(queue_err)?,
                    path: row.try_get("path").map_err(queue_err)?,
                    status: row.try_get("status").map_err(queue_err)?,
                    attempts: row.try_get("attempts").map_err(queue_err)?,
                    last_error: row.try_get("last_error").map_err(queue_err)?,
                    updated_at: row.try_get("updated_at").map_err(queue_err)?,
                })
            })
            .collect::<Result<_, QueueError>>()?;

        Ok(status)
    }
}

/// `#[ignore]`d by default so `cargo test` needs no database; run explicitly
/// with `cargo test -p yunq-infra-postgres -- --ignored` against
/// `DATABASE_URL`, same convention as `lib.rs`'s `live_db_tests` module.
/// `claim_one`/`fail` were previously untested against a real database at
/// all (unlike every sibling adapter module) despite being the exact logic
/// the dead-letter/attempt-tracking behavior depends on.
#[cfg(test)]
mod live_db_tests {
    use super::*;
    use yunq_rules_engine::JobQueue;

    /// Serializes the tests in this module against each other. Unlike the
    /// issue/hotspot tests, which read back rows they select by primary
    /// key, these exercise `claim_one` — and a queue consumer claims the
    /// oldest pending job in the *table*, not one scoped to the caller.
    /// Giving each test a unique project name is therefore not enough to
    /// isolate it: any row another test (or a previously failed run) left
    /// pending is claimed first, and the test fails comparing its own
    /// project against someone else's. That made the outcome depend on
    /// execution order — `--test-threads=1` failed three of the four,
    /// parallel failed a different two.
    static QUEUE_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    /// A connected adapter plus exclusive use of `scan_jobs`, emptied so
    /// the claim order is determined by this test alone. The guard must be
    /// held for the body of the test, so callers bind it rather than
    /// dropping it on the spot.
    async fn exclusive_queue() -> (PgIssueStorage, tokio::sync::MutexGuard<'static, ()>) {
        let guard = QUEUE_LOCK.lock().await;
        let storage = connected_storage().await;
        sqlx::query("DELETE FROM scan_jobs").execute(storage.pool()).await.unwrap();
        (storage, guard)
    }

    async fn connected_storage() -> PgIssueStorage {
        let database_url = std::env::var("DATABASE_URL")
            .unwrap_or_else(|_| "postgres://yunq:yunq@localhost:5432/yunq".to_string());
        let storage = PgIssueStorage::connect_lazy(&database_url).unwrap();
        storage.migrate().await.unwrap();
        storage
    }

    async fn cleanup(storage: &PgIssueStorage, project: &str) {
        sqlx::query("DELETE FROM scan_jobs WHERE project = $1")
            .bind(project)
            .execute(storage.pool())
            .await
            .unwrap();
    }

    #[tokio::test]
    #[ignore = "requires a live Postgres; see module docs"]
    async fn claim_increments_attempts_and_records_project_and_path() {
        let (storage, _queue) = exclusive_queue().await;
        let project = format!(
            "queue-test-claim-{}",
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        );
        storage.enqueue_scan(ScanJob::new(project.clone(), "/src").unwrap()).await.unwrap();
        let consumer = PgJobConsumer::new(storage.pool().clone());

        let (id, job, attempts) = consumer.claim_one().await.unwrap().expect("job was just enqueued");
        assert_eq!(job.project(), project);
        assert_eq!(job.path(), "/src");
        assert_eq!(attempts, 1);

        let status: String = sqlx::query("SELECT status FROM scan_jobs WHERE id = $1")
            .bind(id)
            .fetch_one(storage.pool())
            .await
            .unwrap()
            .try_get("status")
            .unwrap();
        assert_eq!(status, "processing");

        cleanup(&storage, &project).await;
    }

    #[tokio::test]
    #[ignore = "requires a live Postgres; see module docs"]
    async fn failing_below_max_attempts_releases_back_to_pending_with_error() {
        let (storage, _queue) = exclusive_queue().await;
        let project = format!(
            "queue-test-release-{}",
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        );
        storage.enqueue_scan(ScanJob::new(project.clone(), "/src").unwrap()).await.unwrap();
        let consumer = PgJobConsumer::new(storage.pool().clone());

        let (id, _job, attempts) = consumer.claim_one().await.unwrap().unwrap();
        assert_eq!(attempts, 1);
        consumer.fail(id, attempts, "parse error: unexpected token").await.unwrap();

        let row = sqlx::query("SELECT status, last_error FROM scan_jobs WHERE id = $1")
            .bind(id)
            .fetch_one(storage.pool())
            .await
            .unwrap();
        let status: String = row.try_get("status").unwrap();
        let last_error: String = row.try_get("last_error").unwrap();
        assert_eq!(status, "pending");
        assert_eq!(last_error, "parse error: unexpected token");

        cleanup(&storage, &project).await;
    }

    #[tokio::test]
    #[ignore = "requires a live Postgres; see module docs"]
    async fn exhausting_retry_budget_dead_letters_the_job() {
        let (storage, _queue) = exclusive_queue().await;
        let project = format!(
            "queue-test-deadletter-{}",
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        );
        storage.enqueue_scan(ScanJob::new(project.clone(), "/src").unwrap()).await.unwrap();
        let consumer = PgJobConsumer::new(storage.pool().clone());

        // Claim and fail repeatedly until the retry budget is exhausted.
        let mut id = 0i64;
        for _ in 0..DEFAULT_MAX_ATTEMPTS {
            let (claimed_id, _job, attempts) = consumer.claim_one().await.unwrap().expect("job still pending");
            id = claimed_id;
            consumer.fail(id, attempts, "boom").await.unwrap();
        }

        let status: String = sqlx::query("SELECT status FROM scan_jobs WHERE id = $1")
            .bind(id)
            .fetch_one(storage.pool())
            .await
            .unwrap()
            .try_get("status")
            .unwrap();
        assert_eq!(status, "dead");

        // A dead job is never claimed again.
        assert!(consumer.claim_one().await.unwrap().is_none());

        cleanup(&storage, &project).await;
    }

    #[tokio::test]
    #[ignore = "requires a live Postgres; see module docs"]
    async fn queue_status_reports_counts_and_recent_failures() {
        let (storage, _queue) = exclusive_queue().await;
        let project = format!(
            "queue-test-status-{}",
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        );
        storage.enqueue_scan(ScanJob::new(project.clone(), "/src-a").unwrap()).await.unwrap();
        storage.enqueue_scan(ScanJob::new(project.clone(), "/src-b").unwrap()).await.unwrap();
        let consumer = PgJobConsumer::new(storage.pool().clone());

        // `claim_one` always claims the lowest-id pending row, and a failed
        // job (below max attempts) goes right back to `pending` — so
        // `/src-a` (enqueued first, lower id) is reclaimed on every
        // iteration until it dead-letters, and `/src-b` is never touched.
        for _ in 0..DEFAULT_MAX_ATTEMPTS {
            let (id, job, attempts) = consumer.claim_one().await.unwrap().unwrap();
            assert_eq!(job.path(), "/src-a");
            consumer.fail(id, attempts, "always fails").await.unwrap();
        }

        let status = storage.queue_status().await.unwrap();
        assert_eq!(status.dead, 1);
        assert!(status.pending >= 1);
        assert!(status.recent_failures.iter().any(|f| f.project == project
            && f.path == "/src-a"
            && f.status == "dead"
            && f.last_error.as_deref() == Some("always fails")));

        cleanup(&storage, &project).await;
    }
}
