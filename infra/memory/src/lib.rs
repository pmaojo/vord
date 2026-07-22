//! In-memory outbound adapters: used by the CLI (single-process scans) and
//! as test doubles in integration tests.

use std::sync::{Arc, Mutex};

use yunq_rules_engine::{
    Hotspot, HotspotReader, HotspotReview, HotspotStatus, HotspotStorage, Issue, IssueQuery,
    IssueReader, IssueStorage, IssueTransition, IssueWorkflow, Metrics, MetricsTracker, Page,
    StorageError, StoredHotspot, StoredIssue, WorkflowError,
};

#[derive(Clone, Default)]
pub struct InMemoryIssueStorage {
    issues: Arc<Mutex<Vec<Issue>>>,
    hotspots: Arc<Mutex<Vec<Hotspot>>>,
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
    async fn search_issues(&self, query: &IssueQuery) -> Result<Page<StoredIssue>, StorageError> {
        let issues = self.issues.lock().map_err(|e| StorageError(e.to_string()))?;
        let matches: Vec<StoredIssue> = issues
            .iter()
            .enumerate()
            .rev()
            .filter(|(_, issue)| {
                query.severity.is_none_or(|s| issue.severity() == s)
                    && query.status.is_none_or(|s| issue.status() == s)
                    && query.rule.as_ref().is_none_or(|r| issue.rule() == r)
                    && query.file.as_deref().is_none_or(|f| issue.file().contains(f))
                    && query.assignee.as_deref().is_none_or(|a| issue.assignee() == Some(a))
            })
            .map(|(index, issue)| StoredIssue { id: index as i64 + 1, issue: issue.clone() })
            .collect();
        let total = matches.len();
        let items = matches
            .into_iter()
            .skip(query.offset())
            .take(query.normalized_page_size())
            .collect();
        Ok(Page {
            items,
            page: query.normalized_page(),
            page_size: query.normalized_page_size(),
            total,
        })
    }
}

impl HotspotStorage for InMemoryIssueStorage {
    async fn save_hotspots(&self, hotspots: &[Hotspot]) -> Result<(), StorageError> {
        self.hotspots
            .lock()
            .map_err(|e| StorageError(e.to_string()))?
            .extend_from_slice(hotspots);
        Ok(())
    }
}

impl HotspotReader for InMemoryIssueStorage {
    async fn recent_hotspots(&self, limit: usize) -> Result<Vec<StoredHotspot>, StorageError> {
        let hotspots = self.hotspots.lock().map_err(|e| StorageError(e.to_string()))?;
        Ok(hotspots
            .iter()
            .enumerate()
            .rev()
            .take(limit)
            .map(|(index, hotspot)| StoredHotspot { id: index as i64 + 1, hotspot: hotspot.clone() })
            .collect())
    }
}

impl HotspotReview for InMemoryIssueStorage {
    async fn review_hotspot(
        &self,
        hotspot_id: i64,
        status: HotspotStatus,
    ) -> Result<StoredHotspot, WorkflowError> {
        let mut hotspots = self.hotspots.lock().map_err(|e| StorageError(e.to_string()))?;
        let index = usize::try_from(hotspot_id - 1).ok().filter(|i| *i < hotspots.len());
        let Some(index) = index else { return Err(WorkflowError::NotFound(hotspot_id)) };
        hotspots[index].review(status);
        Ok(StoredHotspot { id: hotspot_id, hotspot: hotspots[index].clone() })
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

        let listed =
            futures::executor::block_on(storage.search_issues(&IssueQuery::default())).unwrap();
        assert_eq!(listed.items[0].issue.status(), IssueStatus::Resolved);
        assert_eq!(listed.items[0].issue.assignee(), Some("alice"));

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

    #[test]
    fn search_filters_and_paginates() {
        let storage = InMemoryIssueStorage::new();
        let issue = |rule: &str, severity: Severity, file: &str| {
            Issue::new(RuleId::new(rule).unwrap(), severity, "m", file, Span::new(1, 1, 1, 2))
        };
        futures::executor::block_on(storage.save_issues(&[
            issue("owasp:a", Severity::Blocker, "src/auth.ts"),
            issue("smells:b", Severity::Minor, "src/auth.ts"),
            issue("owasp:a", Severity::Blocker, "lib/util.rs"),
            issue("owasp:a", Severity::Critical, "lib/util.rs"),
        ]))
        .unwrap();

        let by_severity = IssueQuery { severity: Some(Severity::Blocker), ..Default::default() };
        let page = futures::executor::block_on(storage.search_issues(&by_severity)).unwrap();
        assert_eq!(page.total, 2);

        let by_file = IssueQuery { file: Some("auth".into()), ..Default::default() };
        let page = futures::executor::block_on(storage.search_issues(&by_file)).unwrap();
        assert_eq!(page.total, 2);

        let paged = IssueQuery { page: 2, page_size: 3, ..Default::default() };
        let page = futures::executor::block_on(storage.search_issues(&paged)).unwrap();
        assert_eq!(page.total, 4);
        assert_eq!(page.items.len(), 1);
        assert_eq!(page.page, 2);
    }

    #[test]
    fn hotspot_review_roundtrip() {
        let storage = InMemoryIssueStorage::new();
        let hotspot = Hotspot::new(
            RuleId::new("owasp:command-execution").unwrap(),
            "review me",
            "a.rs",
            Span::new(3, 1, 3, 10),
        );
        futures::executor::block_on(storage.save_hotspots(&[hotspot])).unwrap();

        let listed = futures::executor::block_on(storage.recent_hotspots(10)).unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].hotspot.status(), HotspotStatus::ToReview);

        let reviewed =
            futures::executor::block_on(storage.review_hotspot(1, HotspotStatus::Safe)).unwrap();
        assert_eq!(reviewed.hotspot.status(), HotspotStatus::Safe);
        assert!(matches!(
            futures::executor::block_on(storage.review_hotspot(9, HotspotStatus::Safe)),
            Err(WorkflowError::NotFound(9))
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
