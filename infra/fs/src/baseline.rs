//! File-backed New Code baseline: the issue fingerprints of the previous
//! analysis, persisted as JSON beside the scan root. Missing or corrupt
//! files fail open (no baseline → nothing is classified as pre-existing).

use std::path::{Path, PathBuf};

use yunq_rules_engine::Baseline;

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
        let fingerprints: Vec<u64> = serde_json::from_str(&raw).ok()?;
        Some(Baseline::from_fingerprints(fingerprints))
    }

    pub fn save(&self, baseline: &Baseline) -> std::io::Result<()> {
        let fingerprints: Vec<u64> = baseline.fingerprints().collect();
        std::fs::write(&self.path, serde_json::to_string(&fingerprints)?)
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
}
