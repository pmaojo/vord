//! File-backed New Code baseline: the previous analysis's tracked issues,
//! persisted as JSON beside the scan root. Missing or corrupt files fail
//! open (no baseline → nothing is classified as pre-existing).
//!
//! The schema carries a content hash per issue (`line_hash`) alongside the
//! legacy `(rule, file, message)` fingerprint, so `NewCodeAnalysis` can run
//! the content-hash-first tracking cascade instead of only the
//! message-fingerprint fallback. It also carries a display `summary`
//! (rule/file/line/severity/message) so a later `vord scan --show-resolved`
//! can name a closed issue instead of just counting it. Baseline files
//! written by older vord versions — either a bare `Vec<u64>` of
//! fingerprints, or entries with no `summary` field — are still read: the
//! load path tries the current schema first and falls back to the legacy
//! ones, and a missing `summary` simply means that entry can't be named if
//! it's later found resolved (`#[serde(default)]`), so upgrading vord
//! doesn't invalidate an existing baseline.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use vord_rules_engine::{Baseline, IssueSummary, Severity};

#[derive(Serialize, Deserialize)]
struct StoredSummary {
    rule: String,
    severity: String,
    file: String,
    line: u32,
    message: String,
}

impl From<&IssueSummary> for StoredSummary {
    fn from(summary: &IssueSummary) -> Self {
        Self {
            rule: summary.rule.clone(),
            severity: summary.severity.as_str().to_string(),
            file: summary.file.clone(),
            line: summary.line,
            message: summary.message.clone(),
        }
    }
}

impl StoredSummary {
    /// `None` for a severity string a future vord version added and this
    /// one doesn't know — fails open the same way a missing field does.
    fn into_summary(self) -> Option<IssueSummary> {
        Some(IssueSummary {
            rule: self.rule,
            severity: Severity::parse(&self.severity)?,
            file: self.file,
            line: self.line,
            message: self.message,
        })
    }
}

#[derive(Serialize, Deserialize)]
struct StoredEntry {
    rule_file: u64,
    fingerprint: u64,
    line_hash: Option<u64>,
    #[serde(default)]
    summary: Option<StoredSummary>,
}

pub struct BaselineStore {
    path: PathBuf,
}

impl BaselineStore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The previous analysis's baseline, if one was stored and is readable.
    pub fn load(&self) -> Option<Baseline> {
        let raw = std::fs::read_to_string(&self.path).ok()?;
        if let Ok(entries) = serde_json::from_str::<Vec<StoredEntry>>(&raw) {
            return Some(Baseline::from_entries(entries.into_iter().map(|e| {
                (
                    e.rule_file,
                    e.fingerprint,
                    e.line_hash,
                    e.summary.and_then(StoredSummary::into_summary),
                )
            })));
        }
        // Legacy format: a bare array of fingerprints, no content hash.
        let fingerprints: Vec<u64> = serde_json::from_str(&raw).ok()?;
        Some(Baseline::from_fingerprints(fingerprints))
    }

    pub fn save(&self, baseline: &Baseline) -> std::io::Result<()> {
        let entries: Vec<StoredEntry> = baseline
            .entries()
            .map(|(rule_file, fingerprint, line_hash, summary)| StoredEntry {
                rule_file,
                fingerprint,
                line_hash,
                summary: summary.as_ref().map(StoredSummary::from),
            })
            .collect();
        std::fs::write(&self.path, serde_json::to_string(&entries)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrips_and_fails_open() {
        let dir = std::env::temp_dir().join(format!("vord-baseline-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let store = BaselineStore::new(dir.join("baseline.json"));

        assert!(store.load().is_none());
        let baseline = Baseline::from_fingerprints([1u64, 2, 3]);
        store.save(&baseline).unwrap();
        assert_eq!(store.load().unwrap(), baseline);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn reads_a_legacy_bare_fingerprint_file() {
        let dir =
            std::env::temp_dir().join(format!("vord-baseline-legacy-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("baseline.json");
        // What a pre-content-hash vord version wrote: a bare u64 array.
        std::fs::write(&path, "[7,9,42]").unwrap();

        let store = BaselineStore::new(&path);
        let loaded = store.load().expect("legacy format should still load");
        let mut fingerprints: Vec<u64> = loaded.fingerprints().collect();
        fingerprints.sort_unstable();
        assert_eq!(fingerprints, vec![7, 9, 42]);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn summary_roundtrips_through_save_and_load() {
        let dir =
            std::env::temp_dir().join(format!("vord-baseline-summary-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let store = BaselineStore::new(dir.join("baseline.json"));

        let summary = IssueSummary {
            rule: "smells:high-complexity".to_string(),
            severity: Severity::Major,
            file: "src/lib.rs".to_string(),
            line: 42,
            message: "function has cyclomatic complexity 11 (max 10)".to_string(),
        };
        let baseline = Baseline::from_entries([(1u64, 2u64, Some(3u64), Some(summary))]);
        store.save(&baseline).unwrap();
        assert_eq!(store.load().unwrap(), baseline);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_pre_summary_baseline_file_still_loads_with_no_summary() {
        let dir = std::env::temp_dir().join(format!(
            "vord-baseline-pre-summary-test-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("baseline.json");
        // What a pre-`--show-resolved` vord version wrote: entries with no
        // `summary` field at all.
        std::fs::write(&path, r#"[{"rule_file":1,"fingerprint":2,"line_hash":3}]"#).unwrap();

        let store = BaselineStore::new(&path);
        let loaded = store.load().expect("pre-summary format should still load");
        assert_eq!(
            loaded,
            Baseline::from_entries([(1u64, 2u64, Some(3u64), None)])
        );

        std::fs::remove_dir_all(&dir).ok();
    }
}
