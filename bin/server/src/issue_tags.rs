//! Issue tags — the lightweight key-value labels users attach to issues for
//! ad-hoc grouping (e.g. `security/audit`, `team/platform`, `priority/high`).
//! ROADMAP §Phase 3 — "Issue lifecycle: ... tags, bulk changes, changelog
//! per issue".
//!
//! Skeleton: types + a small in-memory store are in place; the Postgres
//! store + HTTP routes land in following iterations.

use std::collections::{HashMap, HashSet};
use serde::{Deserialize, Serialize};

/// One tag on one issue.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct IssueTag {
    pub issue_id: String,
    pub tag: String,
    pub added_by: Option<String>,
    pub added_at: u64,
}

impl IssueTag {
    pub fn new(issue_id: impl Into<String>, tag: impl Into<String>) -> Self {
        Self { issue_id: issue_id.into(), tag: tag.into(), added_by: None, added_at: 0 }
    }

    /// Reject empty / whitespace-only tags, tags with control chars, and
    /// tags longer than 64 chars. Mirrors SonarQube's tag naming rules.
    pub fn is_valid_label(tag: &str) -> bool {
        if tag.is_empty() || tag.len() > 64 { return false; }
        tag.chars().all(|c| !c.is_control() && c != ' ' && c != '\n')
    }
}

/// In-memory store of (issue_id, tag) tuples. Replaced by the Postgres
/// port in a follow-up iteration; the public surface stays identical.
#[derive(Default)]
pub struct IssueTagStore {
    inner: HashMap<String, HashSet<String>>,
}

impl IssueTagStore {
    pub fn add(&mut self, issue_id: &str, tag: &str) -> Result<(), String> {
        if !IssueTag::is_valid_label(tag) {
            return Err(format!("invalid tag {tag:?}"));
        }
        self.inner.entry(issue_id.to_string()).or_default().insert(tag.to_string());
        Ok(())
    }

    pub fn remove(&mut self, issue_id: &str, tag: &str) -> bool {
        let Some(set) = self.inner.get_mut(issue_id) else { return false; };
        let removed = set.remove(tag);
        if set.is_empty() {
            self.inner.remove(issue_id);
        }
        removed
    }

    pub fn tags_for(&self, issue_id: &str) -> Vec<String> {
        let mut v: Vec<String> = self.inner.get(issue_id).cloned().unwrap_or_default().into_iter().collect();
        v.sort();
        v
    }

    pub fn issues_with_tag(&self, tag: &str) -> Vec<String> {
        self.inner.iter()
            .filter(|(_, s)| s.contains(tag))
            .map(|(k, _)| k.clone())
            .collect()
    }

    pub fn len(&self) -> usize { self.inner.len() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_then_list_returns_sorted_unique_tags() {
        let mut s = IssueTagStore::default();
        s.add("i1", "security").unwrap();
        s.add("i1", "audit").unwrap();
        s.add("i1", "security").unwrap();  // duplicate is idempotent
        assert_eq!(s.tags_for("i1"), vec!["audit", "security"]);
    }

    #[test]
    fn remove_cleans_up_empty_issue_entry() {
        let mut s = IssueTagStore::default();
        s.add("i1", "x").unwrap();
        assert_eq!(s.len(), 1);
        assert!(s.remove("i1", "x"));
        assert_eq!(s.len(), 0);
        assert!(!s.remove("i1", "x"));  // already gone
    }

    #[test]
    fn empty_tag_is_rejected() {
        assert!(!IssueTag::is_valid_label(""));
        assert!(!IssueTag::is_valid_label("   "));
    }

    #[test]
    fn tag_over_64_chars_is_rejected() {
        let long = "a".repeat(65);
        assert!(!IssueTag::is_valid_label(&long));
    }

    #[test]
    fn tag_with_whitespace_or_control_char_is_rejected() {
        assert!(!IssueTag::is_valid_label("a b"));
        assert!(!IssueTag::is_valid_label("a\nb"));
        assert!(!IssueTag::is_valid_label("a\tb"));
        assert!(IssueTag::is_valid_label("a-b_c.d"));
    }

    #[test]
    fn add_rejects_invalid_label() {
        let mut s = IssueTagStore::default();
        assert!(s.add("i1", "").is_err());
        assert!(s.add("i1", "has space").is_err());
        assert_eq!(s.tags_for("i1"), Vec::<String>::new());
    }

    #[test]
    fn issues_with_tag_returns_every_issue_carrying_it() {
        let mut s = IssueTagStore::default();
        s.add("i1", "security").unwrap();
        s.add("i2", "security").unwrap();
        s.add("i3", "audit").unwrap();
        let mut issues = s.issues_with_tag("security");
        issues.sort();
        assert_eq!(issues, vec!["i1", "i2"]);
        assert!(s.issues_with_tag("nonexistent").is_empty());
    }
}
