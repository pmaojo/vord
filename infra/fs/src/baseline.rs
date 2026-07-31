//! File-backed New Code baseline: the previous analysis's tracked issues,
//! persisted as JSON beside the scan root. Missing or corrupt files fail
//! open (no baseline → nothing is classified as pre-existing).
//!
//! The schema carries a content hash per issue (`line_hash`) alongside the
//! legacy `(rule, file, message)` fingerprint, so `NewCodeAnalysis` can run
//! the content-hash-first tracking cascade instead of only the
//! message-fingerprint fallback. Baseline files written by older yunq
//! versions (a bare `Vec<u64>` of fingerprints) are still read — the load
//! path tries the current schema first and falls back to the legacy one,
//! so upgrading yunq doesn't invalidate an existing baseline.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use yunq_rules_engine::Baseline;

#[derive(Serialize, Deserialize)]
struct StoredEntry {
    rule_file: u64,
    fingerprint: u64,
    line_hash: Option<u64>,
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
            return Some(Baseline::from_entries(
                entries
                    .into_iter()
                    .map(|e| (e.rule_file, e.fingerprint, e.line_hash)),
            ));
        }
        // Legacy format: a bare array of fingerprints, no content hash.
        let fingerprints: Vec<u64> = serde_json::from_str(&raw).ok()?;
        Some(Baseline::from_fingerprints(fingerprints))
    }

    pub fn save(&self, baseline: &Baseline) -> std::io::Result<()> {
        let entries: Vec<StoredEntry> = baseline
            .entries()
            .map(|(rule_file, fingerprint, line_hash)| StoredEntry {
                rule_file,
                fingerprint,
                line_hash,
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
        let dir = std::env::temp_dir().join(format!("yunq-baseline-test-{}", std::process::id()));
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
            std::env::temp_dir().join(format!("yunq-baseline-legacy-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("baseline.json");
        // What a pre-content-hash yunq version wrote: a bare u64 array.
        std::fs::write(&path, "[7,9,42]").unwrap();

        let store = BaselineStore::new(&path);
        let loaded = store.load().expect("legacy format should still load");
        let mut fingerprints: Vec<u64> = loaded.fingerprints().collect();
        fingerprints.sort_unstable();
        assert_eq!(fingerprints, vec![7, 9, 42]);

        std::fs::remove_dir_all(&dir).ok();
    }
}
