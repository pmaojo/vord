//! Outbound adapter: scan-job queue backed by the same Postgres database as
//! issue storage — no external broker. Producers `INSERT` and `NOTIFY`;
//! consumers claim work with `UPDATE ... FOR UPDATE SKIP LOCKED` (so multiple
//! workers never grab the same row) and `LISTEN` for near-instant wakeup,
//! falling back to a periodic poll in case a notification is missed.

use std::future::Future;
use std::time::Duration;

use sqlx::postgres::PgListener;
use sqlx::{PgPool, Row};
use yunq_rules_engine::{JobQueue, QueueError, ScanJob};

use crate::PgIssueStorage;

const NOTIFY_CHANNEL: &str = "yunq_scan_jobs";
const POLL_FALLBACK: Duration = Duration::from_secs(5);

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
            while let Some((id, job)) = self.claim_one().await? {
                match handle(job).await {
                    Ok(()) => self.delete(id).await?,
                    Err(_) => self.release(id).await?,
                }
            }
            // Either a NOTIFY wakes us immediately, or the fallback timeout
            // re-checks the table (covers jobs enqueued before this listener
            // connected, or a notification lost to a connection hiccup).
            let _ = tokio::time::timeout(POLL_FALLBACK, listener.recv()).await;
        }
    }

    async fn claim_one(&self) -> Result<Option<(i64, ScanJob)>, QueueError> {
        let row = sqlx::query(
            "UPDATE scan_jobs SET status = 'processing'
             WHERE id = (
                 SELECT id FROM scan_jobs
                 WHERE status = 'pending'
                 ORDER BY id ASC
                 FOR UPDATE SKIP LOCKED
                 LIMIT 1
             )
             RETURNING id, project, path",
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
        let job = ScanJob::new(project, path).map_err(queue_err)?;
        Ok(Some((id, job)))
    }

    async fn delete(&self, id: i64) -> Result<(), QueueError> {
        sqlx::query("DELETE FROM scan_jobs WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(queue_err)?;
        Ok(())
    }

    async fn release(&self, id: i64) -> Result<(), QueueError> {
        sqlx::query("UPDATE scan_jobs SET status = 'pending' WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(queue_err)?;
        Ok(())
    }
}
