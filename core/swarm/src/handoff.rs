//! Durable handoff schema for `vord swarm` (roadmap B2). Files under
//! `.vord/handoffs/` (`outbox`/`inbox`/`sent`/`failed`), not direct
//! messaging — a crashed agent loses nothing sitting in a directory, and a
//! malformed handoff lands in `failed` instead of corrupting a peer's
//! context.
//!
//! Pure by construction: this module only knows how to build and validate
//! one handoff's bytes. Which directory a handoff belongs in, and moving it
//! there, is I/O — `infra/fs::handoff` owns that, the same split
//! `core/swarm::worktree`/`infra/fs::swarm_worktree` draws for worktrees.

use serde::{Deserialize, Serialize};

/// One agent-to-agent handoff. Deliberately flat and JSON-serializable —
/// this is a wire format written to disk, not an in-memory domain type with
/// invariants to protect beyond "the required fields are non-empty".
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Handoff {
    /// Unique within the queue; also the filename a caller writes this
    /// handoff under (`<id>.json`), so a sender can regenerate the same id
    /// idempotently instead of writing the same handoff twice.
    pub id: String,
    pub from_role: String,
    pub to_role: String,
    pub summary: String,
    /// The denial DTO from `hook check --format json`, when this handoff
    /// exists to report why a write was refused — "agent B, here is exactly
    /// why your edit was refused" as a structured payload rather than a
    /// bare failure a peer has to re-derive. `core/swarm` never constructs
    /// this itself; it is opaque JSON passed through from whichever denial
    /// produced it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub denial: Option<serde_json::Value>,
    /// Unix seconds. Supplied by the caller — this crate has no clock.
    pub created_at: i64,
}

impl Handoff {
    pub fn new(
        id: impl Into<String>,
        from_role: impl Into<String>,
        to_role: impl Into<String>,
        summary: impl Into<String>,
        created_at: i64,
    ) -> Self {
        Self {
            id: id.into(),
            from_role: from_role.into(),
            to_role: to_role.into(),
            summary: summary.into(),
            denial: None,
            created_at,
        }
    }

    pub fn with_denial(mut self, denial: serde_json::Value) -> Self {
        self.denial = Some(denial);
        self
    }

    /// Pretty JSON — this is a file a human may open mid-incident to see
    /// what one agent told another, so it is written readable rather than
    /// minified.
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).expect("Handoff has no non-serializable field")
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum HandoffError {
    #[error("invalid handoff JSON: {0}")]
    Json(String),
    #[error("handoff is missing `{0}`")]
    MissingField(&'static str),
}

/// Parses and validates one handoff's raw bytes. A handoff that fails here is
/// the caller's cue to land the original bytes in `failed/` rather than
/// route them anywhere — malformed input must never silently vanish, and
/// must never reach a peer's inbox looking well-formed.
pub fn parse_handoff(raw: &str) -> Result<Handoff, HandoffError> {
    let handoff: Handoff =
        serde_json::from_str(raw).map_err(|e| HandoffError::Json(e.to_string()))?;
    if handoff.id.trim().is_empty() {
        return Err(HandoffError::MissingField("id"));
    }
    if handoff.from_role.trim().is_empty() {
        return Err(HandoffError::MissingField("from_role"));
    }
    if handoff.to_role.trim().is_empty() {
        return Err(HandoffError::MissingField("to_role"));
    }
    Ok(handoff)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_handoff_round_trips_through_json() {
        let original = Handoff::new("h1", "coder", "qa", "fixed the xss finding", 1_700_000_000);
        let parsed = parse_handoff(&original.to_json()).expect("valid handoff parses");
        assert_eq!(parsed, original);
    }

    #[test]
    fn a_denial_payload_round_trips_as_opaque_json() {
        let denial = serde_json::json!({ "rule": "owasp:eval-usage", "outcome": "deny" });
        let original =
            Handoff::new("h2", "coder", "architect", "blocked", 1).with_denial(denial.clone());
        let parsed = parse_handoff(&original.to_json()).expect("valid handoff parses");
        assert_eq!(parsed.denial, Some(denial));
    }

    #[test]
    fn a_handoff_with_no_denial_serializes_without_the_field() {
        let handoff = Handoff::new("h3", "coder", "qa", "done", 1);
        assert!(
            !handoff.to_json().contains("denial"),
            "an absent denial should not appear at all"
        );
    }

    #[test]
    fn malformed_json_is_rejected_rather_than_partially_accepted() {
        assert!(matches!(
            parse_handoff("not json"),
            Err(HandoffError::Json(_))
        ));
    }

    #[test]
    fn an_empty_required_field_is_rejected() {
        let raw = r#"{"id":"","from_role":"coder","to_role":"qa","summary":"x","created_at":1}"#;
        assert_eq!(parse_handoff(raw), Err(HandoffError::MissingField("id")));

        let raw = r#"{"id":"h1","from_role":"","to_role":"qa","summary":"x","created_at":1}"#;
        assert_eq!(
            parse_handoff(raw),
            Err(HandoffError::MissingField("from_role"))
        );

        let raw = r#"{"id":"h1","from_role":"coder","to_role":"","summary":"x","created_at":1}"#;
        assert_eq!(
            parse_handoff(raw),
            Err(HandoffError::MissingField("to_role"))
        );
    }
}
