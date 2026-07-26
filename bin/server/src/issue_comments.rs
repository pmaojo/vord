//! Issue comments — the free-text timeline attached to an issue. ROADMAP
//! §Phase 3 — "Issue lifecycle: ... comments, tags, bulk changes, changelog
//! per issue".
//!
//! Comments are distinct from changelog entries: comments are user-written
//! prose ("looks like a duplicate of #1234"); changelog entries are the
//! automated record of transitions/assignments/tags. Both append-only.
//!
//! Skeleton: types + a small in-memory store + a query helper are in
//! place; the Postgres store + HTTP routes land in following iterations.

use std::collections::HashMap;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IssueComment {
    pub id: String,
    pub issue_id: String,
    pub author: String,
    pub body: String,
    pub created_at: u64,
}

impl IssueComment {
    pub fn new(issue_id: impl Into<String>, author: impl Into<String>, body: impl Into<String>) -> Self {
        Self { id: String::new(), issue_id: issue_id.into(), author: author.into(), body: body.into(), created_at: 0 }
    }

    /// Reject empty / whitespace-only bodies and bodies over 8 KiB.
    pub fn is_valid_body(body: &str) -> bool {
        !body.trim().is_empty() && body.len() <= 8 * 1024
    }
}

#[derive(Default)]
pub struct IssueCommentStore {
    by_id: HashMap<String, IssueComment>,
    by_issue: HashMap<String, Vec<String>>,
    next_id: u64,
}

impl IssueCommentStore {
    pub fn add(&mut self, mut c: IssueComment) -> Result<String, String> {
        if !IssueComment::is_valid_body(&c.body) {
            return Err("comment body must be non-empty and <= 8KiB".to_string());
        }
        self.next_id += 1;
        c.id = format!("c{}", self.next_id);
        self.by_issue.entry(c.issue_id.clone()).or_default().push(c.id.clone());
        self.by_id.insert(c.id.clone(), c);
        Ok(self.by_id.get(&c.id.clone().unwrap_or_default()).map(|x| x.id.clone()).unwrap_or_default())
            // (kept the lookup simple; the insert above already moved c by ownership)
    }

    pub fn for_issue(&self, issue_id: &str) -> Vec<IssueComment> {
        self.by_issue.get(issue_id)
            .map(|ids| ids.iter().filter_map(|i| self.by_id.get(i).cloned()).collect())
            .unwrap_or_default()
    }

    pub fn get(&self, id: &str) -> Option<IssueComment> { self.by_id.get(id).cloned() }

    pub fn count(&self) -> usize { self.by_id.len() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_returns_increasing_id() {
        let mut s = IssueCommentStore::default();
        let id1 = s.add(IssueComment::new("i1", "alice", "first")).unwrap();
        let id2 = s.add(IssueComment::new("i1", "bob", "second")).unwrap();
        assert_ne!(id1, id2);
        assert!(id1.starts_with('c'));
        assert!(id2.starts_with('c'));
    }

    #[test]
    fn add_rejects_empty_body() {
        let mut s = IssueCommentStore::default();
        assert!(s.add(IssueComment::new("i1", "alice", "")).is_err());
        assert!(s.add(IssueComment::new("i1", "alice", "   ")).is_err());
    }

    #[test]
    fn add_rejects_oversize_body() {
        let mut s = IssueCommentStore::default();
        let huge = "x".repeat(9 * 1024);
        assert!(s.add(IssueComment::new("i1", "alice", &huge)).is_err());
    }

    #[test]
    fn for_issue_returns_only_that_issues_comments() {
        let mut s = IssueCommentStore::default();
        s.add(IssueComment::new("i1", "alice", "on i1")).unwrap();
        s.add(IssueComment::new("i2", "bob", "on i2")).unwrap();
        let i1 = s.for_issue("i1");
        assert_eq!(i1.len(), 1);
        assert_eq!(i1[0].body, "on i1");
    }

    #[test]
    fn get_returns_full_record_by_id() {
        let mut s = IssueCommentStore::default();
        let id = s.add(IssueComment::new("i1", "alice", "hello")).unwrap();
        let c = s.get(&id).unwrap();
        assert_eq!(c.author, "alice");
        assert_eq!(c.body, "hello");
    }

    #[test]
    fn count_reflects_inserted_comments() {
        let mut s = IssueCommentStore::default();
        assert_eq!(s.count(), 0);
        s.add(IssueComment::new("i1", "alice", "1")).unwrap();
        s.add(IssueComment::new("i1", "alice", "2")).unwrap();
        assert_eq!(s.count(), 2);
    }

    #[test]
    fn body_validation_rules_match_sonarqube_conventions() {
        assert!(IssueComment::is_valid_body("ok"));
        assert!(!IssueComment::is_valid_body(""));
        assert!(!IssueComment::is_valid_body("   "));
        assert!(!IssueComment::is_valid_body(""));
        // exactly 8 KiB is allowed
        assert!(IssueComment::is_valid_body(&"x".repeat(8 * 1024)));
        // 8 KiB + 1 is not
        assert!(!IssueComment::is_valid_body(&"x".repeat(8 * 1024 + 1)));
    }
}
