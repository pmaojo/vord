//! In-memory outbound adapters: used by the CLI (single-process scans) and
//! as test doubles in integration tests.

use std::sync::{Arc, Mutex};

use yunq_rules_engine::{
    Issue, IssueReader, IssueStorage, Metrics, MetricsTracker, StorageError,
};

#[derive(Clone, Default)]
pub struct InMemoryIssueStorage {
    issues: Arc<Mutex<Vec<Issue>>>,
}

impl InMemoryIssueStorage {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn issues(&self) -> Vec<Issue> {
        self.issues.lock().expect("storage lock poisoned").clone()
    }
}

impl IssueStorage for InMemoryIssueStorage {
    async fn save_issues(&self, issues: &[Issue]) -> Result<(), StorageError> {
        self.issues
            .lock()
            .map_err(|e| StorageError(e.to_string()))?
            .extend_from_slice(issues);
        Ok(())
    }
}

impl IssueReader for InMemoryIssueStorage {
    async fn recent_issues(&self, limit: usize) -> Result<Vec<Issue>, StorageError> {
        let issues = self.issues.lock().map_err(|e| StorageError(e.to_string()))?;
        Ok(issues.iter().rev().take(limit).cloned().collect())
    }
}

#[derive(Clone, Default)]
pub struct InMemoryMetricsTracker {
    recorded: Arc<Mutex<Vec<Metrics>>>,
}

impl InMemoryMetricsTracker {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn recorded(&self) -> Vec<Metrics> {
        self.recorded.lock().expect("metrics lock poisoned").clone()
    }
}

impl MetricsTracker for InMemoryMetricsTracker {
    async fn record(&self, metrics: &Metrics) -> Result<(), StorageError> {
        self.recorded
            .lock()
            .map_err(|e| StorageError(e.to_string()))?
            .push(metrics.clone());
        Ok(())
    }
}
