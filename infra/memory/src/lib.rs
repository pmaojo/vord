//! In-memory outbound adapters: used by the CLI (single-process scans) and
//! as test doubles in integration tests.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use yunq_rules_engine::{
    BulkOutcome, ChangelogAction, ChangelogEntry, Hotspot, HotspotReader, HotspotReview,
    HotspotStatus, HotspotStorage, Issue, IssueBulkWorkflow, IssueChangelogReader,
    IssueFacetReader, IssueFacets, IssueQuery, IssueReader, IssueScope, IssueStorage,
    IssueTransition, IssueWorkflow, Metrics, MetricsTracker, Page, RuleId, Severity, StorageError,
    StoredHotspot, StoredIssue, WorkflowError,
};

#[derive(Clone, Default)]
pub struct InMemoryIssueStorage {
    issues: Arc<Mutex<Vec<Issue>>>,
    hotspots: Arc<Mutex<Vec<Hotspot>>>,
    changelog: Arc<Mutex<Vec<ChangelogEntry>>>,
    /// Fake monotonic clock: no wall-clock dependency in this test adapter.
    tick: Arc<AtomicU64>,
}

/// Whether `issue` satisfies `query`'s filters, optionally ignoring one
/// dimension (for facet counts, which exclude their own filter).
enum SkipDimension {
    None,
    Severity,
    Status,
    Rule,
}

fn issue_matches(issue: &Issue, query: &IssueQuery, skip: &SkipDimension) -> bool {
    (matches!(skip, SkipDimension::Severity)
        || query.severity.is_none_or(|s| issue.severity() == s))
        && (matches!(skip, SkipDimension::Status)
            || query.status.is_none_or(|s| issue.status() == s))
        && (matches!(skip, SkipDimension::Rule)
            || query.rule.as_ref().is_none_or(|r| issue.rule() == r))
        && query
            .file
            .as_deref()
            .is_none_or(|f| issue.file().contains(f))
        && query
            .assignee
            .as_deref()
            .is_none_or(|a| issue.assignee() == Some(a))
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
    // This adapter is a single-process, ephemeral test double (CLI local
    // scans, integration test fakes); it has no notion of a project, so the
    // scope is accepted for port-compatibility but not stored.
    async fn save_issues(&self, issues: &[Issue], _scope: IssueScope) -> Result<(), StorageError> {
        self.issues
            .lock()
            .map_err(|e| StorageError(e.to_string()))?
            .extend_from_slice(issues);
        Ok(())
    }
}

impl IssueReader for InMemoryIssueStorage {
    async fn search_issues(&self, query: &IssueQuery) -> Result<Page<StoredIssue>, StorageError> {
        let issues = self
            .issues
            .lock()
            .map_err(|e| StorageError(e.to_string()))?;
        let matches: Vec<StoredIssue> = issues
            .iter()
            .enumerate()
            .rev()
            .filter(|(_, issue)| issue_matches(issue, query, &SkipDimension::None))
            .map(|(index, issue)| StoredIssue {
                id: index as i64 + 1,
                issue: issue.clone(),
            })
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

impl IssueFacetReader for InMemoryIssueStorage {
    async fn facets(&self, query: &IssueQuery) -> Result<IssueFacets, StorageError> {
        let issues = self
            .issues
            .lock()
            .map_err(|e| StorageError(e.to_string()))?;

        let mut by_severity: BTreeMap<Severity, usize> = BTreeMap::new();
        for issue in issues
            .iter()
            .filter(|i| issue_matches(i, query, &SkipDimension::Severity))
        {
            *by_severity.entry(issue.severity()).or_default() += 1;
        }

        let mut status_counts: BTreeMap<String, (yunq_rules_engine::IssueStatus, usize)> =
            BTreeMap::new();
        for issue in issues
            .iter()
            .filter(|i| issue_matches(i, query, &SkipDimension::Status))
        {
            let entry = status_counts
                .entry(issue.status().to_string())
                .or_insert((issue.status(), 0));
            entry.1 += 1;
        }
        let by_status = status_counts.into_values().collect();

        let mut rule_counts: BTreeMap<String, (RuleId, usize)> = BTreeMap::new();
        for issue in issues
            .iter()
            .filter(|i| issue_matches(i, query, &SkipDimension::Rule))
        {
            let entry = rule_counts
                .entry(issue.rule().to_string())
                .or_insert_with(|| (issue.rule().clone(), 0));
            entry.1 += 1;
        }
        let by_rule = rule_counts.into_values().collect();

        Ok(IssueFacets {
            by_severity,
            by_status,
            by_rule,
        })
    }
}

impl IssueBulkWorkflow for InMemoryIssueStorage {
    async fn bulk_transition(
        &self,
        issue_ids: &[i64],
        transition: IssueTransition,
    ) -> Result<Vec<BulkOutcome>, StorageError> {
        let mut outcomes = Vec::with_capacity(issue_ids.len());
        for &issue_id in issue_ids {
            match IssueWorkflow::apply_transition(self, issue_id, transition).await {
                Ok(stored) => outcomes.push(BulkOutcome::Applied(stored)),
                Err(e) => outcomes.push(BulkOutcome::Failed {
                    issue_id,
                    reason: e.to_string(),
                }),
            }
        }
        Ok(outcomes)
    }
}

impl IssueChangelogReader for InMemoryIssueStorage {
    async fn changelog(&self, issue_id: i64) -> Result<Vec<ChangelogEntry>, StorageError> {
        let log = self
            .changelog
            .lock()
            .map_err(|e| StorageError(e.to_string()))?;
        Ok(log
            .iter()
            .filter(|e| e.issue_id == issue_id)
            .cloned()
            .collect())
    }
}

impl HotspotStorage for InMemoryIssueStorage {
    async fn save_hotspots(
        &self,
        hotspots: &[Hotspot],
        _scope: IssueScope,
    ) -> Result<(), StorageError> {
        self.hotspots
            .lock()
            .map_err(|e| StorageError(e.to_string()))?
            .extend_from_slice(hotspots);
        Ok(())
    }
}

impl HotspotReader for InMemoryIssueStorage {
    async fn recent_hotspots(&self, limit: usize) -> Result<Vec<StoredHotspot>, StorageError> {
        let hotspots = self
            .hotspots
            .lock()
            .map_err(|e| StorageError(e.to_string()))?;
        Ok(hotspots
            .iter()
            .enumerate()
            .rev()
            .take(limit)
            .map(|(index, hotspot)| StoredHotspot {
                id: index as i64 + 1,
                hotspot: hotspot.clone(),
            })
            .collect())
    }
}

impl HotspotReview for InMemoryIssueStorage {
    async fn review_hotspot(
        &self,
        hotspot_id: i64,
        status: HotspotStatus,
    ) -> Result<StoredHotspot, WorkflowError> {
        let mut hotspots = self
            .hotspots
            .lock()
            .map_err(|e| StorageError(e.to_string()))?;
        let index = usize::try_from(hotspot_id - 1)
            .ok()
            .filter(|i| *i < hotspots.len());
        let Some(index) = index else {
            return Err(WorkflowError::NotFound(hotspot_id));
        };
        hotspots[index].review(status);
        Ok(StoredHotspot {
            id: hotspot_id,
            hotspot: hotspots[index].clone(),
        })
    }
}

impl InMemoryIssueStorage {
    fn record(&self, entry: ChangelogEntry) {
        if let Ok(mut log) = self.changelog.lock() {
            log.push(entry);
        }
    }

    fn next_tick(&self) -> String {
        format!("t{}", self.tick.fetch_add(1, Ordering::Relaxed))
    }
}

impl IssueWorkflow for InMemoryIssueStorage {
    async fn apply_transition(
        &self,
        issue_id: i64,
        transition: IssueTransition,
    ) -> Result<StoredIssue, WorkflowError> {
        let from = {
            let mut issues = self
                .issues
                .lock()
                .map_err(|e| StorageError(e.to_string()))?;
            let index = usize::try_from(issue_id - 1)
                .ok()
                .filter(|i| *i < issues.len());
            let Some(index) = index else {
                return Err(WorkflowError::NotFound(issue_id));
            };
            let from = issues[index].status();
            issues[index].apply(transition)?;
            from
        };
        self.record(ChangelogEntry {
            issue_id,
            action: ChangelogAction::Transitioned { from, transition },
            at: self.next_tick(),
        });
        let issues = self
            .issues
            .lock()
            .map_err(|e| StorageError(e.to_string()))?;
        Ok(StoredIssue {
            id: issue_id,
            issue: issues[(issue_id - 1) as usize].clone(),
        })
    }

    async fn set_assignee(
        &self,
        issue_id: i64,
        assignee: Option<String>,
    ) -> Result<StoredIssue, WorkflowError> {
        {
            let mut issues = self
                .issues
                .lock()
                .map_err(|e| StorageError(e.to_string()))?;
            let index = usize::try_from(issue_id - 1)
                .ok()
                .filter(|i| *i < issues.len());
            let Some(index) = index else {
                return Err(WorkflowError::NotFound(issue_id));
            };
            match &assignee {
                Some(user) => issues[index].assign(user.clone()),
                None => issues[index].unassign(),
            }
        }
        self.record(ChangelogEntry {
            issue_id,
            action: ChangelogAction::Assigned { assignee },
            at: self.next_tick(),
        });
        let issues = self
            .issues
            .lock()
            .map_err(|e| StorageError(e.to_string()))?;
        Ok(StoredIssue {
            id: issue_id,
            issue: issues[(issue_id - 1) as usize].clone(),
        })
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
        futures::executor::block_on(storage.save_issues(&[issue], IssueScope::default())).unwrap();

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

        // Every successful mutation left a changelog trail.
        let log = futures::executor::block_on(storage.changelog(1)).unwrap();
        assert_eq!(log.len(), 2);
        assert!(matches!(
            log[0].action,
            ChangelogAction::Transitioned { .. }
        ));
        assert!(matches!(log[1].action, ChangelogAction::Assigned { .. }));
    }

    #[test]
    fn bulk_transition_reports_per_issue_outcomes() {
        let storage = InMemoryIssueStorage::new();
        let issue = |file: &str| {
            Issue::new(
                RuleId::new("test:rule").unwrap(),
                Severity::Major,
                "m",
                file,
                Span::new(1, 1, 1, 2),
            )
        };
        futures::executor::block_on(
            storage.save_issues(&[issue("a.rs"), issue("b.rs")], IssueScope::default()),
        )
        .unwrap();

        let outcomes = futures::executor::block_on(
            storage.bulk_transition(&[1, 2, 99], IssueTransition::Confirm),
        )
        .unwrap();
        assert_eq!(outcomes.len(), 3);
        assert!(
            matches!(&outcomes[0], BulkOutcome::Applied(s) if s.issue.status() == IssueStatus::Confirmed)
        );
        assert!(
            matches!(&outcomes[1], BulkOutcome::Applied(s) if s.issue.status() == IssueStatus::Confirmed)
        );
        assert!(matches!(
            &outcomes[2],
            BulkOutcome::Failed { issue_id: 99, .. }
        ));
    }

    #[test]
    fn facets_exclude_their_own_dimension() {
        let storage = InMemoryIssueStorage::new();
        let issue = |rule: &str, severity: Severity| {
            Issue::new(
                RuleId::new(rule).unwrap(),
                severity,
                "m",
                "a.rs",
                Span::new(1, 1, 1, 2),
            )
        };
        futures::executor::block_on(storage.save_issues(
            &[
                issue("owasp:a", Severity::Blocker),
                issue("owasp:a", Severity::Minor),
                issue("smells:b", Severity::Blocker),
            ],
            IssueScope::default(),
        ))
        .unwrap();

        // Filtering by severity=Blocker still shows the FULL severity facet
        // (2 blocker + 1 minor), since severity excludes itself — but the
        // rule facet is computed WITH the severity filter applied, so it
        // only reflects the two blocker issues.
        let query = IssueQuery {
            severity: Some(Severity::Blocker),
            ..Default::default()
        };
        let facets = futures::executor::block_on(storage.facets(&query)).unwrap();
        assert_eq!(facets.by_severity.get(&Severity::Blocker), Some(&2));
        assert_eq!(facets.by_severity.get(&Severity::Minor), Some(&1));
        let rule_counts: std::collections::HashMap<_, _> = facets
            .by_rule
            .iter()
            .map(|(r, c)| (r.as_str().to_string(), *c))
            .collect();
        assert_eq!(rule_counts.get("owasp:a"), Some(&1));
        assert_eq!(rule_counts.get("smells:b"), Some(&1));
    }

    #[test]
    fn search_filters_and_paginates() {
        let storage = InMemoryIssueStorage::new();
        let issue = |rule: &str, severity: Severity, file: &str| {
            Issue::new(
                RuleId::new(rule).unwrap(),
                severity,
                "m",
                file,
                Span::new(1, 1, 1, 2),
            )
        };
        futures::executor::block_on(storage.save_issues(
            &[
                issue("owasp:a", Severity::Blocker, "src/auth.ts"),
                issue("smells:b", Severity::Minor, "src/auth.ts"),
                issue("owasp:a", Severity::Blocker, "lib/util.rs"),
                issue("owasp:a", Severity::Critical, "lib/util.rs"),
            ],
            IssueScope::default(),
        ))
        .unwrap();

        let by_severity = IssueQuery {
            severity: Some(Severity::Blocker),
            ..Default::default()
        };
        let page = futures::executor::block_on(storage.search_issues(&by_severity)).unwrap();
        assert_eq!(page.total, 2);

        let by_file = IssueQuery {
            file: Some("auth".into()),
            ..Default::default()
        };
        let page = futures::executor::block_on(storage.search_issues(&by_file)).unwrap();
        assert_eq!(page.total, 2);

        let paged = IssueQuery {
            page: 2,
            page_size: 3,
            ..Default::default()
        };
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
        futures::executor::block_on(storage.save_hotspots(&[hotspot], IssueScope::default()))
            .unwrap();

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

/// In-memory `Sandbox` adapter: applies a proposal against pre-loaded file
/// content without touching any real filesystem or git worktree. Used where
/// there's no local checkout to sandbox in, e.g. the server, which persists
/// issues in Postgres and fetches source on demand from GitHub rather than
/// keeping a working tree on disk.
#[derive(Default)]
pub struct InMemorySandbox {
    files: Mutex<BTreeMap<std::path::PathBuf, String>>,
    originals: Mutex<BTreeMap<std::path::PathBuf, String>>,
}

impl InMemorySandbox {
    /// Seeds the sandbox with a single file's known-good content.
    pub fn with_file(path: impl Into<std::path::PathBuf>, content: impl Into<String>) -> Self {
        let mut files = BTreeMap::new();
        files.insert(path.into(), content.into());
        Self {
            files: Mutex::new(files),
            originals: Mutex::new(BTreeMap::new()),
        }
    }
}

impl yunq_remediation::Sandbox for InMemorySandbox {
    fn apply_proposal(
        &self,
        proposal: &yunq_remediation::FixProposal,
    ) -> Result<(), yunq_remediation::RemediationError> {
        if proposal.original_snippet.is_empty() {
            return Err(yunq_remediation::RemediationError::SandboxError(
                "proposal snippet must not be empty".to_string(),
            ));
        }
        let mut files = self
            .files
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let source = files.get(&proposal.file_path).cloned().ok_or_else(|| {
            yunq_remediation::RemediationError::SandboxError(format!(
                "no sandboxed content for {}",
                proposal.file_path.display()
            ))
        })?;
        let occurrences = source.matches(&proposal.original_snippet).count();
        if occurrences != 1 {
            return Err(yunq_remediation::RemediationError::SandboxError(format!(
                "proposal snippet must match exactly once, matched {occurrences} times"
            )));
        }
        let updated = source.replacen(&proposal.original_snippet, &proposal.replacement_snippet, 1);
        self.originals
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .entry(proposal.file_path.clone())
            .or_insert(source);
        files.insert(proposal.file_path.clone(), updated);
        Ok(())
    }

    fn read_source(
        &self,
        file_path: &std::path::Path,
    ) -> Result<String, yunq_remediation::RemediationError> {
        self.files
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(file_path)
            .cloned()
            .ok_or_else(|| {
                yunq_remediation::RemediationError::SandboxError(format!(
                    "no sandboxed content for {}",
                    file_path.display()
                ))
            })
    }

    fn rollback(&self) -> Result<(), yunq_remediation::RemediationError> {
        let originals = std::mem::take(
            &mut *self
                .originals
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()),
        );
        let mut files = self
            .files
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        for (path, content) in originals {
            files.insert(path, content);
        }
        Ok(())
    }
}

#[cfg(test)]
mod in_memory_sandbox_tests {
    use std::path::PathBuf;

    use yunq_remediation::{FixProposal, Sandbox};

    use super::InMemorySandbox;

    fn proposal(original: &str, replacement: &str) -> FixProposal {
        FixProposal {
            file_path: PathBuf::from("src/lib.rs"),
            explanation: "test".to_string(),
            original_snippet: original.to_string(),
            replacement_snippet: replacement.to_string(),
        }
    }

    #[test]
    fn applies_reads_and_rolls_back() {
        let sandbox = InMemorySandbox::with_file("src/lib.rs", "let value = 1;\n");
        sandbox.apply_proposal(&proposal("1", "2")).unwrap();
        assert_eq!(
            sandbox.read_source(&PathBuf::from("src/lib.rs")).unwrap(),
            "let value = 2;\n"
        );

        sandbox.rollback().unwrap();
        assert_eq!(
            sandbox.read_source(&PathBuf::from("src/lib.rs")).unwrap(),
            "let value = 1;\n"
        );
    }

    #[test]
    fn rejects_ambiguous_snippet() {
        let sandbox = InMemorySandbox::with_file("src/lib.rs", "let a = 1;\nlet b = 1;\n");
        let err = sandbox.apply_proposal(&proposal("1", "2")).unwrap_err();
        assert!(matches!(
            err,
            yunq_remediation::RemediationError::SandboxError(_)
        ));
    }
}
