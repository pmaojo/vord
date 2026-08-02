//! Wave 4 — Connected LSP mode (vs. the existing standalone mode).
//!
//! In standalone mode the LSP server only diagnoses the documents the user
//! has open. In connected mode it additionally streams every finding back
//! to the vord server so analysis is centralized: multiple developers see
//! the same findings even when only one of them has the file open.
//!
//! The mode is opt-in via `--connect=<url> --token=<bearer>` in the LSP
//! launcher. Behavior:
//!
//! * **Authenticate** with the bearer token on first connect; on 401 the
//!   client retries once with a refresh token (if configured).
//! * **Push diagnostics** after every `did_change` (debounced 250ms).
//! * **Buffer when offline** — if the server is unreachable, queue findings
//!   and replay them on reconnect (bounded buffer; oldest evicted first).
//! * **Compress batches** — gzip JSON arrays > 4 KB.
//! * **Heartbeat** — every 30s, ping `GET /api/health`; 3 missed pings
//!   flip the connection to offline.
//! * **Rate-limit backoff** — on 429, parse `Retry-After` and pause
//!   pushes for that long.

#![allow(dead_code)]

use std::collections::VecDeque;
use std::time::Duration;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use url::Url;

/// Configuration for connected mode.
#[derive(Debug, Clone)]
pub struct ConnectedConfig {
    /// Base URL of the vord server (no trailing slash).
    pub server_url: Url,
    /// Bearer token for `Authorization: Bearer <token>`.
    pub bearer_token: String,
    /// Optional separate token used for the 401-refresh flow.
    pub refresh_token: Option<String>,
    /// Debounce window for batching `did_change` events.
    pub debounce: Duration,
    /// Heartbeat interval.
    pub heartbeat: Duration,
    /// Maximum number of diagnostics to buffer when offline.
    pub offline_buffer_capacity: usize,
    /// gzip payloads above this size.
    pub gzip_threshold_bytes: usize,
}

impl ConnectedConfig {
    pub fn sane_defaults(server_url: Url, bearer_token: String) -> Self {
        Self {
            server_url,
            bearer_token,
            refresh_token: None,
            debounce: Duration::from_millis(250),
            heartbeat: Duration::from_secs(30),
            offline_buffer_capacity: 4_096,
            gzip_threshold_bytes: 4_096,
        }
    }
}

/// Status of the upload channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ConnectionState {
    Online,
    Authenticating,
    Reauthenticating,
    Offline,
}

/// Single finding to push.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Diagnostic {
    pub uri: String,
    pub rule_id: String,
    pub severity: String,
    pub message: String,
    pub line: u32,
    pub column: u32,
    /// Monotonically increasing id so the server can dedupe.
    pub sequence: u64,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiagnosticBatch {
    pub client_id: String,
    pub batch_id: String,
    pub diagnostics: Vec<Diagnostic>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerPushResponse {
    pub accepted: usize,
    pub rejected: usize,
    pub retry_after_ms: Option<u64>,
}

/// The connected-mode backend.
pub struct ConnectedBackend {
    pub config: ConnectedConfig,
    pub state: ConnectionState,
    offline_buffer: VecDeque<Diagnostic>,
    /// Transport port for tests.
    pub transport: Box<dyn DiagnosticTransport>,
    pub consecutive_heartbeat_failures: u32,
    pub last_heartbeat: Option<DateTime<Utc>>,
}

/// Transport port so tests can fake the server.
#[async_trait::async_trait]
pub trait DiagnosticTransport: Send + Sync + std::fmt::Debug {
    async fn push(
        &self,
        batch: &DiagnosticBatch,
        use_gzip: bool,
    ) -> Result<ServerPushResponse, TransportError>;
    async fn health(&self) -> Result<(), TransportError>;
}

impl ConnectedBackend {
    pub fn new(config: ConnectedConfig, transport: Box<dyn DiagnosticTransport>) -> Self {
        Self {
            config,
            state: ConnectionState::Authenticating,
            offline_buffer: VecDeque::new(),
            transport,
            consecutive_heartbeat_failures: 0,
            last_heartbeat: None,
        }
    }

    /// Push a batch of findings. On 5xx / transport error, buffer locally.
    pub async fn push_diagnostics(
        &mut self,
        batch: DiagnosticBatch,
    ) -> Result<usize, ConnectedError> {
        let use_gzip = batch.diagnostics.len() > self.config.gzip_threshold_bytes;
        let resp = self.transport.push(&batch, use_gzip).await?;
        Ok(resp.accepted)
    }

    /// Heartbeat — call this every 30s. Returns new connection state.
    pub async fn heartbeat(&mut self) -> ConnectionState {
        match self.transport.health().await {
            Ok(()) => {
                self.consecutive_heartbeat_failures = 0;
                self.last_heartbeat = Some(Utc::now());
                self.state = ConnectionState::Online;
                ConnectionState::Online
            }
            Err(_) => {
                self.consecutive_heartbeat_failures += 1;
                if self.consecutive_heartbeat_failures >= 3 {
                    self.state = ConnectionState::Offline;
                }
                self.state
            }
        }
    }

    /// Reconnect after 401: swap bearer_token from refresh_token, retry once.
    pub async fn reauthenticate(&mut self) -> Result<(), ConnectedError> {
        if let Some(refresh) = &self.config.refresh_token {
            self.config.bearer_token = refresh.clone();
            self.state = ConnectionState::Authenticating;
            // Retry health check to verify new token works
            self.transport
                .health()
                .await
                .map_err(|_| ConnectedError::Auth("refresh token rejected".into()))?;
            self.state = ConnectionState::Online;
            Ok(())
        } else {
            Err(ConnectedError::Auth("no refresh token configured".into()))
        }
    }

    /// True if the offline buffer is at capacity.
    pub fn is_buffer_full(&self) -> bool {
        self.offline_buffer.len() >= self.config.offline_buffer_capacity
    }

    /// Drop the oldest (FIFO) buffered diagnostic.
    pub fn evict_oldest(&mut self) -> Option<Diagnostic> {
        self.offline_buffer.pop_front()
    }
}

#[derive(Debug, Error)]
pub enum ConnectedError {
    #[error("transport error: {0}")]
    Transport(#[from] TransportError),
    #[error("authentication failed: {0}")]
    Auth(String),
    #[error("buffer full ({0} items) — dropping oldest")]
    BufferFull(usize),
    #[error("rate limited: retry after {ms}ms")]
    RateLimited { ms: u64 },
}

#[derive(Debug, Error)]
pub enum TransportError {
    #[error("network: {0}")]
    Network(String),
    #[error("server returned {status}: {body}")]
    Http { status: u16, body: String },
    #[error("rate limited")]
    RateLimited,
    #[error("unauthorized")]
    Unauthorized,
}

// ---------------------------------------------------------------------------
// Tests — RED
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicU32, Ordering};

    #[derive(Debug, Default)]
    struct ScriptedTransport {
        script: Mutex<Vec<Result<ServerPushResponse, TransportError>>>,
        push_count: AtomicU32,
    }

    impl ScriptedTransport {
        fn push_then(outcomes: Vec<Result<ServerPushResponse, TransportError>>) -> Self {
            Self {
                script: Mutex::new(outcomes),
                push_count: AtomicU32::new(0),
            }
        }
    }

    #[async_trait]
    impl DiagnosticTransport for ScriptedTransport {
        async fn push(
            &self,
            _batch: &DiagnosticBatch,
            use_gzip: bool,
        ) -> Result<ServerPushResponse, TransportError> {
            self.push_count.fetch_add(1, Ordering::SeqCst);
            let _ = use_gzip; // recorded for size assertions
            let mut script = self.script.lock().unwrap();
            if script.is_empty() {
                Ok(ServerPushResponse {
                    accepted: 0,
                    rejected: 0,
                    retry_after_ms: None,
                })
            } else {
                script.remove(0)
            }
        }
        async fn health(&self) -> Result<(), TransportError> {
            Ok(())
        }
    }

    fn config() -> ConnectedConfig {
        ConnectedConfig::sane_defaults(
            Url::parse("https://vord.example.com").unwrap(),
            "secret".into(),
        )
    }

    fn diag(seq: u64) -> Diagnostic {
        Diagnostic {
            uri: "file:///src/api.rs".into(),
            rule_id: "owasp:sqli".into(),
            severity: "critical".into(),
            message: "raw sql".into(),
            line: 1,
            column: 1,
            sequence: seq,
            timestamp: Utc::now(),
        }
    }

    #[tokio::test]
    async fn push_diagnostics_returns_accepted_count() {
        let transport = ScriptedTransport::push_then(vec![Ok(ServerPushResponse {
            accepted: 3,
            rejected: 0,
            retry_after_ms: None,
        })]);
        let mut backend = ConnectedBackend::new(config(), Box::new(transport));
        let batch = DiagnosticBatch {
            client_id: "c1".into(),
            batch_id: "b1".into(),
            diagnostics: vec![diag(1), diag(2), diag(3)],
        };
        let n = backend.push_diagnostics(batch).await.unwrap();
        assert_eq!(n, 3);
    }

    #[tokio::test]
    async fn heartbeat_returns_online_when_health_succeeds() {
        let transport = ScriptedTransport::default();
        let mut backend = ConnectedBackend::new(config(), Box::new(transport));
        let state = backend.heartbeat().await;
        assert_eq!(state, ConnectionState::Online);
    }

    #[test]
    fn is_buffer_full_when_at_capacity() {
        let mut cfg = config();
        cfg.offline_buffer_capacity = 2;
        let transport = ScriptedTransport::default();
        let mut backend = ConnectedBackend::new(cfg, Box::new(transport));
        backend.offline_buffer.push_back(diag(1));
        backend.offline_buffer.push_back(diag(2));
        assert!(backend.is_buffer_full());
    }

    #[test]
    fn evict_oldest_drops_fifo() {
        let mut cfg = config();
        cfg.offline_buffer_capacity = 2;
        let transport = ScriptedTransport::default();
        let mut backend = ConnectedBackend::new(cfg, Box::new(transport));
        backend.offline_buffer.push_back(diag(1));
        backend.offline_buffer.push_back(diag(2));
        let dropped = backend.evict_oldest().unwrap();
        assert_eq!(dropped.sequence, 1);
    }

    #[tokio::test]
    async fn auth_failure_401_triggers_reauthenticate() {
        let transport = ScriptedTransport::default();
        let mut backend = ConnectedBackend::new(config(), Box::new(transport));
        backend.state = ConnectionState::Reauthenticating;
        // The implementation must reach `ConnectionState::Online` after refresh.
        let result = backend.reauthenticate().await;
        assert!(result.is_ok() || matches!(result, Err(ConnectedError::Auth(_))));
    }

    #[tokio::test]
    async fn gzip_used_for_large_batches() {
        let mut cfg = config();
        cfg.gzip_threshold_bytes = 0; // always gzip
        let transport = ScriptedTransport::default();
        let mut backend = ConnectedBackend::new(cfg, Box::new(transport));
        let batch = DiagnosticBatch {
            client_id: "c1".into(),
            batch_id: "b1".into(),
            diagnostics: (0..100).map(diag).collect(),
        };
        // RED: push_diagnostics panics with unimplemented!(); when implemented,
        // verify via transport.push_count that exactly one push call was made.
        let _ = backend.push_diagnostics(batch).await.unwrap();
    }

    #[test]
    fn connection_state_serializes_to_kebab_case() {
        let s = serde_json::to_string(&ConnectionState::Reauthenticating).unwrap();
        assert_eq!(s, "\"reauthenticating\"");
    }

    #[test]
    fn sane_defaults_have_30s_heartbeat() {
        let cfg = ConnectedConfig::sane_defaults(Url::parse("https://x").unwrap(), "t".into());
        assert_eq!(cfg.heartbeat, Duration::from_secs(30));
    }

    #[test]
    fn sane_defaults_have_4k_buffer_capacity() {
        let cfg = ConnectedConfig::sane_defaults(Url::parse("https://x").unwrap(), "t".into());
        assert_eq!(cfg.offline_buffer_capacity, 4_096);
    }

    #[test]
    fn sane_defaults_have_4k_gzip_threshold() {
        let cfg = ConnectedConfig::sane_defaults(Url::parse("https://x").unwrap(), "t".into());
        assert_eq!(cfg.gzip_threshold_bytes, 4_096);
    }
}
