//! Wave 4 — Tamper-evident audit log via SHA-256 hash chain.
//!
//! Every entry in the audit log is sealed against the previous entry by
//! `hash_n = sha256(prev_hash || canonical_json(entry_n))`. The genesis
//! entry has a well-defined `prev_hash = [0; 32]`.
//!
//! `AuditChain::verify` walks the entire chain and returns:
//! * `Ok(())` if every link is intact,
//! * `Err(TamperDetected { sequence, .. })` at the *first* broken link.
//!
//! This is the foundation of the SOC 2 / ISO 27001 evidence trail: a
//! compromised database that rewrites history without re-sealing every
//! subsequent entry will be caught on the next integrity check.
//!
//! Built on top of the existing `AuditLogEntry` (single row in `audit_log`),
//! so the chain sealing is purely a derived layer — historical rows remain
//! readable.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::audit::AuditLogEntry;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// 32-byte SHA-256 hash.
pub type Hash = [u8; 32];

/// One sealed entry in the audit chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditChainEntry {
    /// Monotonically increasing sequence number (starts at 0 for genesis).
    pub sequence: u64,
    /// The underlying audit log row this entry seals.
    pub entry: AuditLogEntry,
    /// Hash of the previous entry, or `[0; 32]` for the genesis entry.
    pub prev_hash: Hash,
    /// `sha256(prev_hash || canonical_json(entry))`.
    pub hash: Hash,
    /// Optional reference to the original id of the database row.
    pub row_id: i64,
}

impl AuditChainEntry {
    /// Build an entry from a previous hash and a database row. Computes the
    /// canonical-JSON hash so callers cannot accidentally desync.
    pub fn seal(
        prev_hash: Hash,
        sequence: u64,
        row_id: i64,
        entry: AuditLogEntry,
    ) -> Result<Self, AuditChainError> {
        let canonical = serde_json::to_vec(&entry).map_err(AuditChainError::Canonicalize)?;
        let mut hasher = Sha256::new();
        hasher.update(prev_hash);
        hasher.update(&canonical);
        let hash = hasher.finalize().into();
        Ok(Self {
            sequence,
            entry,
            prev_hash,
            hash,
            row_id,
        })
    }

    /// Verify this entry's hash against its `prev_hash` + payload.
    pub fn verify(&self) -> Result<(), AuditChainError> {
        let canonical = serde_json::to_vec(&self.entry).map_err(AuditChainError::Canonicalize)?;
        let mut hasher = Sha256::new();
        hasher.update(self.prev_hash);
        hasher.update(&canonical);
        let expected: Hash = hasher.finalize().into();
        if expected != self.hash {
            return Err(AuditChainError::TamperDetected {
                sequence: self.sequence,
                expected_hash: expected,
                actual_hash: self.hash,
            });
        }
        Ok(())
    }
}

/// Wraps a sequence of `AuditChainEntry` and provides whole-chain verification.
#[derive(Debug, Default, Clone)]
pub struct AuditChain {
    entries: Vec<AuditChainEntry>,
}

impl AuditChain {
    pub fn new() -> Self {
        Self::default()
    }

    /// Append a new entry, sealing it against the previous entry's hash.
    /// Genesis entry is sealed against `[0; 32]`.
    pub fn append(
        &mut self,
        row_id: i64,
        entry: AuditLogEntry,
    ) -> Result<&AuditChainEntry, AuditChainError> {
        let (prev_hash, sequence) = match self.entries.last() {
            None => ([0u8; 32], 0),
            Some(prev) => (prev.hash, prev.sequence + 1),
        };
        let entry = AuditChainEntry::seal(prev_hash, sequence, row_id, entry)?;
        self.entries.push(entry);
        Ok(self.entries.last().expect("just pushed"))
    }

    /// Replay the entire chain; return the first broken link or `Ok(())`.
    pub fn verify(&self) -> Result<(), AuditChainError> {
        let mut prev_hash: Hash = [0u8; 32];
        for entry in &self.entries {
            if entry.prev_hash != prev_hash {
                return Err(AuditChainError::LinkBroken {
                    sequence: entry.sequence,
                });
            }
            entry.verify()?;
            prev_hash = entry.hash;
        }
        Ok(())
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn iter(&self) -> std::slice::Iter<'_, AuditChainEntry> {
        self.entries.iter()
    }
}

impl AuditChain {
    /// Test-only mutable accessor. The production surface area is the
    /// `append` API; this exists only so RED tests can simulate tampering.
    #[cfg(test)]
    pub fn entries_mut_for_test(&mut self) -> &mut Vec<AuditChainEntry> {
        &mut self.entries
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, Error)]
pub enum AuditChainError {
    #[error("entry {sequence} hash mismatch (expected {expected_hash:?}, got {actual_hash:?})")]
    TamperDetected {
        sequence: u64,
        expected_hash: Hash,
        actual_hash: Hash,
    },
    #[error("entry {sequence} prev_hash does not match predecessor")]
    LinkBroken { sequence: u64 },
    #[error("failed to canonicalize entry: {0}")]
    Canonicalize(serde_json::Error),
}

// Manual PartialEq/Eq — serde_json::Error does not implement them, so we
// compare on discriminant + fields of the variants that support it, and
// return false for Canonicalize (which wraps an uncomparable error).
impl PartialEq for AuditChainError {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::TamperDetected { sequence: s1, expected_hash: e1, actual_hash: a1 },
             Self::TamperDetected { sequence: s2, expected_hash: e2, actual_hash: a2 }) => {
                s1 == s2 && e1 == e2 && a1 == a2
            }
            (Self::LinkBroken { sequence: s1 }, Self::LinkBroken { sequence: s2 }) => s1 == s2,
            (Self::Canonicalize(_), Self::Canonicalize(_)) => false,
            _ => false,
        }
    }
}
impl Eq for AuditChainError {}

// ---------------------------------------------------------------------------
// Tests — RED
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn row(id: i64, action: &str) -> (i64, AuditLogEntry) {
        let entry = AuditLogEntry {
            id,
            actor_user_id: Some("user-1".into()),
            action: action.into(),
            entity_type: "permission".into(),
            entity_id: "role:admin".into(),
            before: Some(json!({"roles": []})),
            after: Some(json!({"roles": ["admin"]})),
            created_at: "2026-07-25T00:00:00Z".into(),
        };
        (id, entry)
    }

    #[test]
    fn genesis_hash_is_zero() {
        let mut chain = AuditChain::new();
        let (id, entry) = row(1, "user.login");
        chain.append(id, entry).unwrap();
        let first = chain.iter().next().unwrap();
        assert_eq!(first.sequence, 0);
        assert_eq!(first.prev_hash, [0u8; 32]);
    }

    #[test]
    fn chain_links_via_sha256() {
        let mut chain = AuditChain::new();
        let (id0, e0) = row(1, "user.login");
        let (id1, e1) = row(2, "role.granted");
        chain.append(id0, e0).unwrap();
        chain.append(id1, e1).unwrap();
        let entries: Vec<_> = chain.iter().collect();
        let prev_hash = entries[0].hash;
        let next = entries[1];
        let canonical = serde_json::to_vec(&next.entry).unwrap();
        let mut hasher = Sha256::new();
        hasher.update(prev_hash);
        hasher.update(&canonical);
        let expected: Hash = hasher.finalize().into();
        assert_eq!(next.prev_hash, prev_hash);
        assert_eq!(next.hash, expected);
    }

    #[test]
    fn verify_succeeds_on_clean_chain() {
        let mut chain = AuditChain::new();
        for i in 0..5 {
            let (id, entry) = row(i + 1, "user.login");
            chain.append(id, entry).unwrap();
        }
        assert!(chain.verify().is_ok());
    }

    #[test]
    fn verify_returns_zero_on_empty_chain() {
        let chain = AuditChain::new();
        assert!(chain.verify().is_ok());
    }

    #[test]
    fn tampering_with_payload_invalidates_entry() {
        let mut chain = AuditChain::new();
        let (id0, e0) = row(1, "user.login");
        let (id1, e1) = row(2, "role.granted");
        chain.append(id0, e0).unwrap();
        chain.append(id1, e1).unwrap();
        // Swap entry 1's action name.
        let entries = chain.entries_mut_for_test();
        entries[1].entry.action = "user.logout".into();
        let err = chain.verify().unwrap_err();
        assert!(matches!(err, AuditChainError::TamperDetected { sequence: 1, .. }));
    }

    #[test]
    fn tampering_with_prev_hash_breaks_link() {
        let mut chain = AuditChain::new();
        let (id0, e0) = row(1, "user.login");
        let (id1, e1) = row(2, "role.granted");
        chain.append(id0, e0).unwrap();
        chain.append(id1, e1).unwrap();
        let entries = chain.entries_mut_for_test();
        entries[1].prev_hash = [7u8; 32];
        let err = chain.verify().unwrap_err();
        assert!(matches!(err, AuditChainError::LinkBroken { sequence: 1 }));
    }

    #[test]
    fn verify_returns_first_break_index() {
        let mut chain = AuditChain::new();
        for i in 0..5 {
            let (id, entry) = row(i + 1, "quality_gate.evaluated");
            chain.append(id, entry).unwrap();
        }
        let entries = chain.entries_mut_for_test();
        entries[3].entry.action = "user.logout".into();
        let err = chain.verify().unwrap_err();
        if let AuditChainError::TamperDetected { sequence, .. } = err {
            assert_eq!(sequence, 3);
        } else {
            panic!("expected TamperDetected at sequence 3");
        }
    }

    #[test]
    fn seal_is_deterministic_for_same_payload() {
        let prev: Hash = [1u8; 32];
        let (_id, entry) = row(1, "user.login");
        let a = AuditChainEntry::seal(prev, 1, 1, entry.clone()).unwrap();
        let b = AuditChainEntry::seal(prev, 1, 1, entry).unwrap();
        assert_eq!(a.hash, b.hash);
        assert_eq!(a.prev_hash, b.prev_hash);
    }

    #[test]
    fn seal_changes_when_only_payload_changes() {
        let prev: Hash = [0u8; 32];
        let (_id0, e0) = row(1, "user.login");
        let (_id1, e1) = row(2, "user.logout");
        let a = AuditChainEntry::seal(prev, 0, 1, e0).unwrap();
        let b = AuditChainEntry::seal(prev, 0, 2, e1).unwrap();
        assert_ne!(a.hash, b.hash);
    }

    #[test]
    fn append_increments_sequence_monotonically() {
        let mut chain = AuditChain::new();
        for i in 0..10 {
            let (id, entry) = row(i + 1, "user.login");
            chain.append(id, entry).unwrap();
            let last = chain.iter().last().unwrap();
            assert_eq!(last.sequence, i as u64);
        }
    }

    #[test]
    fn chain_width_grows_with_appends() {
        let mut chain = AuditChain::new();
        assert_eq!(chain.len(), 0);
        let (id0, e0) = row(1, "user.login");
        chain.append(id0, e0).unwrap();
        assert_eq!(chain.len(), 1);
        let (id1, e1) = row(2, "user.login");
        chain.append(id1, e1).unwrap();
        assert_eq!(chain.len(), 2);
    }
}
