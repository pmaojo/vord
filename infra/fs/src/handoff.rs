//! Durable handoff queue for `vord swarm` (roadmap B2) — the I/O half of
//! `vord_swarm::handoff`, which only parses and validates one handoff's
//! bytes. Four directories under `.vord/handoffs/`, adapted from
//! swarm-forge's protocol:
//!
//! - `outbox/` — a sender has written a handoff, not yet delivered.
//! - `inbox/<role>/` — delivered to a specific role's mailbox, not yet
//!   acknowledged.
//! - `sent/` — acknowledged: the recipient has read it and is done with it.
//! - `failed/` — bytes that did not parse as a valid [`Handoff`]. Kept, not
//!   discarded, so a malformed handoff is a visible incident rather than
//!   silently lost mail.
//!
//! A crashed agent loses nothing sitting in any of these — every operation
//! here is "read a file, then rename it", and a rename within the same
//! filesystem is atomic, so there is no window where a handoff exists in two
//! places or none.

use std::path::{Path, PathBuf};

use vord_swarm::{Handoff, parse_handoff};

#[derive(Debug, thiserror::Error)]
pub enum HandoffIoError {
    #[error("io error at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

fn io_err(path: &Path, source: std::io::Error) -> HandoffIoError {
    HandoffIoError::Io {
        path: path.to_path_buf(),
        source,
    }
}

fn queue_dir(root: &Path, name: &str) -> PathBuf {
    root.join(".vord").join("handoffs").join(name)
}

fn ensure_dir(dir: &Path) -> Result<(), HandoffIoError> {
    std::fs::create_dir_all(dir).map_err(|e| io_err(dir, e))
}

/// Writes a handoff into the sender's outbox. Filed as `<id>.json`, so
/// sending the same `id` twice overwrites rather than duplicates — the
/// caller's cue that ids should be assigned once and reused on retry, not
/// regenerated per attempt.
pub fn send(root: &Path, handoff: &Handoff) -> Result<PathBuf, HandoffIoError> {
    let dir = queue_dir(root, "outbox");
    ensure_dir(&dir)?;
    let path = dir.join(format!("{}.json", handoff.id));
    std::fs::write(&path, handoff.to_json()).map_err(|e| io_err(&path, e))?;
    Ok(path)
}

/// Every file currently sitting in a queue directory, sorted by filename so
/// delivery order is deterministic — swarm agents replaying a run need the
/// same order every time, not whatever the filesystem's iteration happens to
/// return.
fn list_files(dir: &Path) -> Result<Vec<PathBuf>, HandoffIoError> {
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let mut entries: Vec<PathBuf> = std::fs::read_dir(dir)
        .map_err(|e| io_err(dir, e))?
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "json"))
        .collect();
    entries.sort();
    Ok(entries)
}

/// Moves a malformed file's original bytes into `failed/` under its own
/// filename — never rewritten, so whatever a human opens there is exactly
/// what the sender wrote, not vord's interpretation of it.
fn quarantine(root: &Path, path: &Path) -> Result<(), HandoffIoError> {
    let dir = queue_dir(root, "failed");
    ensure_dir(&dir)?;
    let target = dir.join(path.file_name().expect("queue files always have a name"));
    std::fs::rename(path, &target).map_err(|e| io_err(path, e))
}

/// Moves every handoff currently in the outbox to its recipient's inbox
/// (`inbox/<to_role>/`), quarantining anything that fails to parse. Returns
/// the handoffs that were actually delivered, in delivery order.
pub fn deliver(root: &Path) -> Result<Vec<Handoff>, HandoffIoError> {
    let outbox = queue_dir(root, "outbox");
    let mut delivered = Vec::new();
    for path in list_files(&outbox)? {
        let raw = std::fs::read_to_string(&path).map_err(|e| io_err(&path, e))?;
        match parse_handoff(&raw) {
            Ok(handoff) => {
                let target_dir = queue_dir(root, "inbox").join(&handoff.to_role);
                ensure_dir(&target_dir)?;
                let target = target_dir.join(format!("{}.json", handoff.id));
                std::fs::rename(&path, &target).map_err(|e| io_err(&path, e))?;
                delivered.push(handoff);
            }
            Err(_) => quarantine(root, &path)?,
        }
    }
    Ok(delivered)
}

/// Every handoff currently waiting in `role`'s inbox, in delivery order.
/// Malformed entries (which should not occur — `deliver` already validated
/// them — but a hand-edited or externally-written file could still land
/// here) are quarantined the same way `deliver` quarantines outbox entries,
/// rather than surfaced as an error that would hide every well-formed
/// handoff behind it.
pub fn inbox(root: &Path, role: &str) -> Result<Vec<Handoff>, HandoffIoError> {
    let dir = queue_dir(root, "inbox").join(role);
    let mut handoffs = Vec::new();
    for path in list_files(&dir)? {
        let raw = std::fs::read_to_string(&path).map_err(|e| io_err(&path, e))?;
        match parse_handoff(&raw) {
            Ok(handoff) => handoffs.push(handoff),
            Err(_) => quarantine(root, &path)?,
        }
    }
    Ok(handoffs)
}

/// Acknowledges one handoff: moves it from `role`'s inbox to `sent/`. A
/// no-op error (not a panic) when the id is not actually in that inbox —
/// double-acking after a crash-and-retry must be safe.
pub fn ack(root: &Path, role: &str, id: &str) -> Result<(), HandoffIoError> {
    let source = queue_dir(root, "inbox")
        .join(role)
        .join(format!("{id}.json"));
    if !source.exists() {
        return Ok(());
    }
    let dir = queue_dir(root, "sent");
    ensure_dir(&dir)?;
    let target = dir.join(format!("{id}.json"));
    std::fs::rename(&source, &target).map_err(|e| io_err(&source, e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_root() -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "vord-handoff-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&root).unwrap();
        root
    }

    #[test]
    fn a_sent_handoff_is_delivered_to_its_recipients_inbox() {
        let root = temp_root();
        let handoff = Handoff::new("h1", "coder", "qa", "please review", 1);
        send(&root, &handoff).unwrap();

        let delivered = deliver(&root).unwrap();
        assert_eq!(delivered, vec![handoff.clone()]);

        let waiting = inbox(&root, "qa").unwrap();
        assert_eq!(waiting, vec![handoff]);
        assert!(
            inbox(&root, "coder").unwrap().is_empty(),
            "delivery is scoped to the addressed role"
        );

        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn delivery_empties_the_outbox() {
        let root = temp_root();
        send(&root, &Handoff::new("h1", "coder", "qa", "x", 1)).unwrap();
        deliver(&root).unwrap();
        assert!(list_files(&queue_dir(&root, "outbox")).unwrap().is_empty());
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn a_malformed_outbox_entry_is_quarantined_not_delivered() {
        let root = temp_root();
        let outbox = queue_dir(&root, "outbox");
        std::fs::create_dir_all(&outbox).unwrap();
        std::fs::write(outbox.join("bad.json"), "not json").unwrap();

        let delivered = deliver(&root).unwrap();
        assert!(delivered.is_empty());
        let failed = list_files(&queue_dir(&root, "failed")).unwrap();
        assert_eq!(failed.len(), 1);
        assert_eq!(std::fs::read_to_string(&failed[0]).unwrap(), "not json");

        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn acking_moves_a_handoff_from_inbox_to_sent() {
        let root = temp_root();
        send(&root, &Handoff::new("h1", "coder", "qa", "x", 1)).unwrap();
        deliver(&root).unwrap();

        ack(&root, "qa", "h1").unwrap();

        assert!(inbox(&root, "qa").unwrap().is_empty());
        assert!(queue_dir(&root, "sent").join("h1.json").exists());

        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn acking_an_unknown_id_is_a_harmless_no_op() {
        let root = temp_root();
        ack(&root, "qa", "does-not-exist").expect("must not error on a double-ack after a crash");
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn sending_the_same_id_twice_overwrites_rather_than_duplicates() {
        let root = temp_root();
        send(&root, &Handoff::new("h1", "coder", "qa", "first", 1)).unwrap();
        send(&root, &Handoff::new("h1", "coder", "qa", "second", 2)).unwrap();

        let delivered = deliver(&root).unwrap();
        assert_eq!(delivered.len(), 1);
        assert_eq!(delivered[0].summary, "second");

        std::fs::remove_dir_all(&root).ok();
    }
}
