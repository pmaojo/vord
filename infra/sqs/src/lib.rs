//! Outbound adapter: scan-job queueing over SQS (`aws-sdk-sqs`).
//!
//! Works unchanged against real AWS or a local emulator (floci/LocalStack):
//! set `YUNQ_AWS_ENDPOINT_URL=http://localhost:4566` to target the emulator.
//! The wire format (`ScanJobDto`) lives here, at the edge; incoming payloads
//! are translated into the domain through `ScanJob::new`, never deserialized
//! into domain types directly.

use std::future::Future;

use aws_sdk_sqs::Client;
use aws_sdk_sqs::config::Credentials;
use serde::{Deserialize, Serialize};
use yunq_rules_engine::{JobQueue, QueueError, ScanJob};

pub const ENDPOINT_ENV_VAR: &str = "YUNQ_AWS_ENDPOINT_URL";

/// Builds an SQS client from the ambient AWS configuration, honoring
/// `YUNQ_AWS_ENDPOINT_URL` for emulators (with dummy static credentials).
pub async fn sqs_client_from_env() -> Client {
    let mut loader = aws_config::defaults(aws_config::BehaviorVersion::latest());
    if let Ok(endpoint) = std::env::var(ENDPOINT_ENV_VAR) {
        loader = loader
            .endpoint_url(endpoint)
            .credentials_provider(Credentials::new("test", "test", None, None, "yunq-emulator"))
            .region(aws_config::Region::new("us-east-1"));
    }
    Client::new(&loader.load().await)
}

#[derive(Serialize, Deserialize)]
struct ScanJobDto {
    project: String,
    path: String,
}

impl From<&ScanJob> for ScanJobDto {
    fn from(job: &ScanJob) -> Self {
        Self { project: job.project().to_string(), path: job.path().to_string() }
    }
}

#[derive(Clone)]
pub struct SqsJobQueue {
    client: Client,
    queue_url: String,
}

impl SqsJobQueue {
    pub fn new(client: Client, queue_url: impl Into<String>) -> Self {
        Self { client, queue_url: queue_url.into() }
    }
}

impl JobQueue for SqsJobQueue {
    async fn enqueue_scan(&self, job: ScanJob) -> Result<(), QueueError> {
        let body = serde_json::to_string(&ScanJobDto::from(&job))
            .map_err(|e| QueueError(e.to_string()))?;
        self.client
            .send_message()
            .queue_url(&self.queue_url)
            .message_body(body)
            .send()
            .await
            .map_err(|e| QueueError(e.to_string()))?;
        Ok(())
    }
}

/// Long-polling consumer. Successfully handled jobs are deleted from the
/// queue; malformed payloads are deleted as poison messages; handler failures
/// leave the message for redelivery.
pub struct SqsJobConsumer {
    client: Client,
    queue_url: String,
}

impl SqsJobConsumer {
    pub fn new(client: Client, queue_url: impl Into<String>) -> Self {
        Self { client, queue_url: queue_url.into() }
    }

    pub async fn listen<F, Fut>(&self, mut handle: F) -> Result<(), QueueError>
    where
        F: FnMut(ScanJob) -> Fut,
        Fut: Future<Output = Result<(), QueueError>>,
    {
        loop {
            let received = self
                .client
                .receive_message()
                .queue_url(&self.queue_url)
                .wait_time_seconds(20)
                .max_number_of_messages(5)
                .send()
                .await
                .map_err(|e| QueueError(e.to_string()))?;

            for message in received.messages.unwrap_or_default() {
                let job = message
                    .body()
                    .and_then(|body| serde_json::from_str::<ScanJobDto>(body).ok())
                    .and_then(|dto| ScanJob::new(dto.project, dto.path).ok());
                let handled = match job {
                    Some(job) => handle(job).await.is_ok(),
                    // Poison message: unparseable payloads are dropped so they
                    // don't loop through the queue forever.
                    None => true,
                };
                if handled && let Some(receipt) = message.receipt_handle() {
                    self.client
                        .delete_message()
                        .queue_url(&self.queue_url)
                        .receipt_handle(receipt)
                        .send()
                        .await
                        .map_err(|e| QueueError(e.to_string()))?;
                }
            }
        }
    }
}
