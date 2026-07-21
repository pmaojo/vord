//! In-memory outbound adapters: used by the CLI (single-process scans) and
//! as test doubles in integration tests.

use std::sync::{Arc, Mutex};

use yunq_rules_engine::{
    Issue, IssueReader, IssueStorage, IssueTransition, IssueWorkflow, Metrics, MetricsTracker,
    StorageError, StoredIssue, WorkflowError,
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
    async fn recent_issues(&self, limit: usize) -> Result<Vec<StoredIssue>, StorageError> {
        let issues = self.issues.lock().map_err(|e| StorageError(e.to_string()))?;
        Ok(issues
            .iter()
            .enumerate()
            .rev()
            .take(limit)
            .map(|(index, issue)| StoredIssue { id: index as i64 + 1, issue: issue.clone() })
            .collect())
    }
}

impl IssueWorkflow for InMemoryIssueStorage {
    async fn apply_transition(
        &self,
        issue_id: i64,
        transition: IssueTransition,
    ) -> Result<StoredIssue, WorkflowError> {
        let mut issues = self.issues.lock().map_err(|e| StorageError(e.to_string()))?;
        let index = usize::try_from(issue_id - 1).ok().filter(|i| *i < issues.len());
        let Some(index) = index else { return Err(WorkflowError::NotFound(issue_id)) };
        issues[index].apply(transition)?;
        Ok(StoredIssue { id: issue_id, issue: issues[index].clone() })
    }

    async fn set_assignee(
        &self,
        issue_id: i64,
        assignee: Option<String>,
    ) -> Result<StoredIssue, WorkflowError> {
        let mut issues = self.issues.lock().map_err(|e| StorageError(e.to_string()))?;
        let index = usize::try_from(issue_id - 1).ok().filter(|i| *i < issues.len());
        let Some(index) = index else { return Err(WorkflowError::NotFound(issue_id)) };
        match assignee {
            Some(user) => issues[index].assign(user),
            None => issues[index].unassign(),
        }
        Ok(StoredIssue { id: issue_id, issue: issues[index].clone() })
    }
}

#[cfg(test)]
mod tests {
    use yunq_ast::Span;
    use yunq_rules_engine::{IssueStatus, Resolution, RuleId, Severity};

    use super::*;

    #[test]
    fn workflow_transitions_persist_in_memory() {
        let storage = InMemoryIssueStorage::new();
        let issue = Issue::new(
            RuleId::new("test:rule").unwrap(),
            Severity::Major,
            "msg",
            "a.rs",
            Span::new(1, 1, 1, 2),
        );
        futures::executor::block_on(storage.save_issues(&[issue])).unwrap();

        let stored = futures::executor::block_on(
            storage.apply_transition(1, IssueTransition::Resolve(Resolution::WontFix)),
        )
        .unwrap();
        assert_eq!(stored.issue.status(), IssueStatus::Resolved);

        let assigned =
            futures::executor::block_on(storage.set_assignee(1, Some("alice".into()))).unwrap();
        assert_eq!(assigned.issue.assignee(), Some("alice"));

        let listed = futures::executor::block_on(storage.recent_issues(10)).unwrap();
        assert_eq!(listed[0].issue.status(), IssueStatus::Resolved);
        assert_eq!(listed[0].issue.assignee(), Some("alice"));

        // Unknown id and illegal transition both surface as errors.
        assert!(matches!(
            futures::executor::block_on(storage.apply_transition(99, IssueTransition::Confirm)),
            Err(WorkflowError::NotFound(99))
        ));
        assert!(matches!(
            futures::executor::block_on(storage.apply_transition(1, IssueTransition::Confirm)),
            Err(WorkflowError::InvalidTransition(_))
        ));
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
