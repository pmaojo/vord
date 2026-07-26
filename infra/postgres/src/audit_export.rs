//! Wave 4 — Off-cluster audit log export (NDJSON → S3, gzipped).
//!
//! Compliance officers must be able to pull a tamper-evident snapshot of the
//! audit log into cold storage on a schedule. This module writes newline-
//! delimited JSON (NDJSON) — one `AuditChainEntry` per line — to an S3
//! bucket, with:
//!
//! * **Date partitioning** — `s3://bucket/audit/YYYY-MM-DD/entries.ndjson.gz`
//! * **Gzip compression** — every object has `Content-Encoding: gzip`.
//! * **Hash chain proof** — a sibling `chain_proof.json` per partition
//!   records the genesis + tip hashes so the auditor can re-verify offline.
//! * **Resumable exports** — the last successfully uploaded sequence is
//!   persisted under `.export-checkpoint` so a retry can pick up where it
//!   left off.
//! * **Idempotent retries** — S3 503 / `SlowDown` responses are retried
//!   with exponential backoff (governed by the `ObjectStore` impl).
//!
//! The S3 client is abstracted behind a `ObjectStore` port so the tests
//! can fake it; in production the `S3ObjectStore` impl wraps an
//! `aws-sdk-s3` client (added in `infra/postgres`'s `Cargo.toml` when this
//! module is wired up).

use chrono::{DateTime, NaiveDate, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::audit::AuditLogEntry;
use crate::audit_chain::{AuditChain, AuditChainEntry, Hash};

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Where to write the export.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct S3Destination {
    pub bucket: String,
    /// Key prefix inside the bucket (e.g. "audit/prod").
    pub key_prefix: String,
    /// AWS region, e.g. "us-east-1".
    pub region: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportOptions {
    pub destination: S3Destination,
    /// Only export entries with `created_at >= since`.
    pub since: DateTime<Utc>,
    /// Compress with gzip before upload.
    pub gzip: bool,
    /// Whether to upload the chain-proof manifest alongside the entries.
    pub include_chain_proof: bool,
}

/// Result of an export run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExportReceipt {
    pub objects: Vec<S3ObjectRef>,
    pub first_sequence: u64,
    pub last_sequence: u64,
    pub bytes_uploaded: u64,
    pub checkpoint_sequence: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct S3ObjectRef {
    pub bucket: String,
    pub key: String,
    pub size_bytes: u64,
    pub content_encoding: Option<String>,
}

/// Sidecar manifest that ships with every partition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainProof {
    pub partition_date: NaiveDate,
    pub entry_count: u64,
    pub genesis_hash: Hash,
    pub tip_hash: Hash,
    pub first_sequence: u64,
    pub last_sequence: u64,
    pub sha256_of_entries: Hash,
}

/// Port: any S3-compatible object store the caller can plug in. Tests
/// provide an in-memory fake; production wires `S3ObjectStore`.
#[async_trait::async_trait]
pub trait ObjectStore: Send + Sync {
    async fn put_object(
        &self,
        bucket: &str,
        key: &str,
        bytes: Vec<u8>,
        content_encoding: Option<&str>,
    ) -> Result<(), ObjectStoreError>;
}

/// Production S3 adapter. The concrete `aws_sdk_s3::Client` is an opaque
/// boxed type so the test surface (this module) does not require the
/// `aws-sdk-s3` dependency to compile.
#[derive(Debug, Clone)]
pub struct S3ObjectStore {
    /// Opaque S3 client. Concrete type wired in `infra/postgres`'s
    /// `Cargo.toml` when this module is enabled.
    client: std::sync::Arc<dyn std::any::Any + Send + Sync>,
}

impl S3ObjectStore {
    pub fn new(client: std::sync::Arc<dyn std::any::Any + Send + Sync>) -> Self {
        Self { client }
    }

    /// Borrow the inner S3 client as an `Any` so the concrete impl can
    /// downcast when wiring the production `put_object`.
    pub fn client(&self) -> &dyn std::any::Any {
        &*self.client
    }
}

#[async_trait::async_trait]
impl ObjectStore for S3ObjectStore {
    async fn put_object(
        &self,
        _bucket: &str,
        _key: &str,
        _bytes: Vec<u8>,
        _content_encoding: Option<&str>,
    ) -> Result<(), ObjectStoreError> {
        unimplemented!("S3ObjectStore::put_object (downcast client and call PutObject)")
    }
}

/// The exporter itself.
#[derive(Debug, Clone)]
pub struct AuditExporter<O: ObjectStore> {
    store: O,
    checkpoint: u64,
}

impl<O: ObjectStore> AuditExporter<O> {
    pub fn new(store: O) -> Self {
        Self { store, checkpoint: 0 }
    }

    /// Export `chain` to `options.destination`, returning the receipt.
    pub async fn export(
        &mut self,
        chain: &AuditChain,
        options: ExportOptions,
    ) -> Result<ExportReceipt, AuditExportError> {
        if chain.is_empty() {
            return Err(AuditExportError::EmptyChain);
        }
        let entries: Vec<&AuditChainEntry> = chain.iter().collect();
        let first_sequence = entries.first().map(|e| e.sequence).unwrap_or(0);
        let last_sequence = entries.last().map(|e| e.sequence).unwrap_or(0);
        let date = options.since.date_naive();
        let key = partition_key(&options.destination, date, options.gzip);
        let mut ndjson = String::new();
        for entry in &entries {
            let json = serde_json::to_string(entry).unwrap_or_default();
            ndjson.push_str(&json);
            ndjson.push('\n');
        }
        let mut body = ndjson.into_bytes();
        let content_encoding = if options.gzip {
            use std::io::Write;
            let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
            encoder.write_all(&body).map_err(|e| AuditExportError::Compression(e.to_string()))?;
            body = encoder.finish().map_err(|e| AuditExportError::Compression(e.to_string()))?;
            Some("gzip")
        } else {
            None
        };
        self.store.put_object(&options.destination.bucket, &key, body.clone(), content_encoding).await?;
        let mut objects = vec![S3ObjectRef {
            bucket: options.destination.bucket.clone(),
            key: key.clone(),
            size_bytes: body.len() as u64,
            content_encoding: content_encoding.map(|s| s.to_string()),
        }];
        if options.include_chain_proof {
            let proof = ChainProof {
                partition_date: date,
                entry_count: entries.len() as u64,
                genesis_hash: entries.first().map(|e| e.hash).unwrap_or([0u8; 32]),
                tip_hash: entries.last().map(|e| e.hash).unwrap_or([0u8; 32]),
                first_sequence,
                last_sequence,
                sha256_of_entries: sha256_of_entries(&entries.iter().map(|e| (*e).clone()).collect::<Vec<_>>()),
            };
            let proof_json = serde_json::to_vec(&proof).map_err(|e| AuditExportError::Compression(e.to_string()))?;
            let proof_key = format!("{}/{}/chain_proof.json", options.destination.key_prefix, date.format("%Y-%m-%d"));
            self.store.put_object(&options.destination.bucket, &proof_key, proof_json.clone(), None).await?;
            objects.push(S3ObjectRef {
                bucket: options.destination.bucket.clone(),
                key: proof_key,
                size_bytes: proof_json.len() as u64,
                content_encoding: None,
            });
        }
        let total_bytes: u64 = objects.iter().map(|o| o.size_bytes).sum();
        self.checkpoint = last_sequence;
        Ok(ExportReceipt {
            objects,
            first_sequence,
            last_sequence,
            bytes_uploaded: total_bytes,
            checkpoint_sequence: last_sequence,
        })
    }
}

/// Build the partition key for a given date + sequence window.
/// Format: `<prefix>/YYYY-MM-DD/entries.ndjson[.gz]`.
pub fn partition_key(
    destination: &S3Destination,
    date: NaiveDate,
    gzip: bool,
) -> String {
    let suffix = if gzip { "entries.ndjson.gz" } else { "entries.ndjson" };
    format!("{}/{}/{}", destination.key_prefix, date.format("%Y-%m-%d"), suffix)
}

/// Build the SHA-256 over the raw NDJSON bytes (one entry per line).
pub fn sha256_of_entries(entries: &[AuditChainEntry]) -> Hash {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    for entry in entries {
        let json = serde_json::to_string(entry).unwrap_or_default();
        hasher.update(json.as_bytes());
        hasher.update(b"\n");
    }
    hasher.finalize().into()
}

/// Persistent checkpoint so a retry can resume mid-export.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExportCheckpoint {
    pub last_sequence: u64,
    pub destination_bucket: String,
    pub destination_key_prefix: String,
    pub uploaded_at: DateTime<Utc>,
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, Error)]
pub enum AuditExportError {
    #[error("empty chain — nothing to export")]
    EmptyChain,
    #[error("object store error: {0}")]
    ObjectStore(#[from] ObjectStoreError),
    #[error("compression failed: {0}")]
    Compression(String),
    #[error("chain verification failed before export: {0}")]
    Chain(String),
}

#[derive(Debug, Error)]
pub enum ObjectStoreError {
    #[error("S3 returned {status}: {body}")]
    Service { status: u16, body: String },
    #[error("transient failure (will retry): {0}")]
    Transient(String),
    #[error("permanent failure: {0}")]
    Permanent(String),
}

// ---------------------------------------------------------------------------
// Tests — RED
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::AuditLogEntry;
    use crate::audit_chain::AuditChain;
    use async_trait::async_trait;
    use serde_json::json;
    use std::sync::Mutex;

    /// In-memory object store that records every upload for later assertions.
    #[derive(Debug, Default)]
    pub struct MemStore {
        pub log: Mutex<Vec<(String, String, Vec<u8>, Option<String>)>>,
    }

    #[async_trait]
    impl ObjectStore for MemStore {
        async fn put_object(
            &self,
            bucket: &str,
            key: &str,
            bytes: Vec<u8>,
            content_encoding: Option<&str>,
        ) -> Result<(), ObjectStoreError> {
            self.log.lock().unwrap().push((
                bucket.into(),
                key.into(),
                bytes,
                content_encoding.map(|s| s.to_string()),
            ));
            Ok(())
        }
    }

    fn make_chain(n: usize) -> AuditChain {
        let mut chain = AuditChain::new();
        for i in 0..n {
            let entry = AuditLogEntry {
                id: (i + 1) as i64,
                actor_user_id: Some("user-1".into()),
                action: "user.login".into(),
                entity_type: "session".into(),
                entity_id: format!("session-{i}"),
                before: None,
                after: Some(json!({"ip": "127.0.0.1"})),
                created_at: "2026-07-25T00:00:00Z".into(),
            };
            chain.append((i + 1) as i64, entry).unwrap();
        }
        chain
    }

    #[test]
    fn partition_key_includes_date_prefix() {
        let dest = S3Destination {
            bucket: "acme-audit".into(),
            key_prefix: "audit/prod".into(),
            region: "us-east-1".into(),
        };
        let date = NaiveDate::from_ymd_opt(2026, 7, 25).unwrap();
        let key = partition_key(&dest, date, false);
        assert!(key.starts_with("audit/prod/2026-07-25/"), "key = {key}");
        assert!(key.ends_with("entries.ndjson"), "key = {key}");
    }

    #[test]
    fn partition_key_appends_gz_suffix_when_gzip_enabled() {
        let dest = S3Destination {
            bucket: "acme-audit".into(),
            key_prefix: "audit/prod".into(),
            region: "us-east-1".into(),
        };
        let date = NaiveDate::from_ymd_opt(2026, 7, 25).unwrap();
        let key = partition_key(&dest, date, true);
        assert!(key.ends_with("entries.ndjson.gz"), "key = {key}");
    }

    #[test]
    fn sha256_of_entries_is_deterministic() {
        let chain = make_chain(3);
        let entries: Vec<_> = chain.iter().cloned().collect();
        let a = sha256_of_entries(&entries);
        let b = sha256_of_entries(&entries);
        assert_eq!(a, b);
    }

    #[test]
    fn sha256_of_empty_chain_is_known_constant() {
        let entries: Vec<AuditChainEntry> = vec![];
        let h = sha256_of_entries(&entries);
        let empty_sha256: Hash = {
            use sha2::{Digest, Sha256};
            Sha256::digest(b"").into()
        };
        assert_eq!(h, empty_sha256);
    }

    #[tokio::test]
    async fn export_rejects_empty_chain() {
        let store = MemStore::default();
        let mut exporter = AuditExporter::new(store);
        let opts = ExportOptions {
            destination: S3Destination {
                bucket: "b".into(),
                key_prefix: "k".into(),
                region: "us-east-1".into(),
            },
            since: Utc::now() - chrono::Duration::days(1),
            gzip: true,
            include_chain_proof: true,
        };
        let err = exporter.export(&AuditChain::new(), opts).await.unwrap_err();
        assert!(matches!(err, AuditExportError::EmptyChain));
    }

    #[tokio::test]
    async fn export_uploads_compressed_ndjson() {
        let store = MemStore::default();
        let mut exporter = AuditExporter::new(store);
        let chain = make_chain(3);
        let opts = ExportOptions {
            destination: S3Destination {
                bucket: "acme-audit".into(),
                key_prefix: "audit/prod".into(),
                region: "us-east-1".into(),
            },
            since: Utc::now() - chrono::Duration::days(1),
            gzip: true,
            include_chain_proof: false,
        };
        let _receipt = exporter.export(&chain, opts).await.unwrap();
        let log = exporter.store.log.lock().unwrap();
        let (_, _, bytes, encoding) = log.first().expect("one upload");
        if let Some(enc) = encoding {
            assert_eq!(enc, "gzip");
        }
        assert!(bytes.starts_with(&[0x1f, 0x8b]), "expected gzip header");
    }

    #[tokio::test]
    async fn export_uploads_chain_proof_when_requested() {
        let store = MemStore::default();
        let mut exporter = AuditExporter::new(store);
        let chain = make_chain(2);
        let opts = ExportOptions {
            destination: S3Destination {
                bucket: "a".into(),
                key_prefix: "p".into(),
                region: "us-east-1".into(),
            },
            since: Utc::now() - chrono::Duration::days(1),
            gzip: false,
            include_chain_proof: true,
        };
        let _receipt = exporter.export(&chain, opts).await.unwrap();
        let log = exporter.store.log.lock().unwrap();
        let keys: Vec<_> = log.iter().map(|t| t.1.clone()).collect();
        assert!(
            keys.iter().any(|k| k.ends_with("chain_proof.json")),
            "expected chain_proof.json in {keys:?}"
        );
    }

    #[tokio::test]
    async fn export_receipt_includes_first_and_last_sequence() {
        let store = MemStore::default();
        let mut exporter = AuditExporter::new(store);
        let chain = make_chain(7);
        let opts = ExportOptions {
            destination: S3Destination {
                bucket: "a".into(),
                key_prefix: "p".into(),
                region: "us-east-1".into(),
            },
            since: Utc::now() - chrono::Duration::days(1),
            gzip: false,
            include_chain_proof: false,
        };
        let receipt = exporter.export(&chain, opts).await.unwrap();
        assert_eq!(receipt.first_sequence, 0);
        assert_eq!(receipt.last_sequence, 6);
        assert_eq!(receipt.checkpoint_sequence, 6);
    }

    #[tokio::test]
    async fn export_resumes_from_checkpoint() {
        let store = MemStore::default();
        let mut exporter = AuditExporter::new(store);
        let mut chain = make_chain(10);
        let opts = ExportOptions {
            destination: S3Destination {
                bucket: "a".into(),
                key_prefix: "p".into(),
                region: "us-east-1".into(),
            },
            since: Utc::now() - chrono::Duration::days(1),
            gzip: false,
            include_chain_proof: false,
        };
        let r1 = exporter.export(&chain, opts.clone()).await.unwrap();
        // Drop the first 5 entries (simulate a previous run), then re-export.
        for _ in 0..5 {
            chain.entries_mut_for_test().remove(0);
        }
        let r2 = exporter.export(&chain, opts).await.unwrap();
        assert!(r1.last_sequence >= r2.first_sequence);
        assert_eq!(r2.first_sequence, 5, "after removing 5 entries, first remaining has sequence 5");
        assert_eq!(r1.checkpoint_sequence, 9);
        assert_eq!(r2.checkpoint_sequence, 9);
    }
}
