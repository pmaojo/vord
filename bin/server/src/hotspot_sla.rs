//! Hotspot SLA tracking + review-rate metrics. ROADMAP §Phase 3 —
//! "Security hotspots ... distinct finding type with to-review/
//! acknowledged/fixed/safe workflow and review metrics".
//!
//! Skeleton: the SLA policy, the breach detector, and the per-project
//! review-rate counter are in place; the persistence + HTTP surface land
//! in following iterations.

#![allow(dead_code)]

use serde::{Deserialize, Serialize};

/// SLA windows by severity — how long a hotspot can sit in `ToReview`
/// before being considered breached. Maps roughly to SonarQube's default.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HotspotSlaPolicy {
    pub blocker_hours: u32,
    pub critical_hours: u32,
    pub major_hours: u32,
    pub minor_hours: u32,
    pub info_hours: u32,
}

impl Default for HotspotSlaPolicy {
    fn default() -> Self {
        // Sensible defaults: a blocker must be reviewed in 24h, a critical
        // in 72h, etc.
        Self {
            blocker_hours: 24,
            critical_hours: 72,
            major_hours: 24 * 7,
            minor_hours: 24 * 30,
            info_hours: 24 * 90,
        }
    }
}

impl HotspotSlaPolicy {
    pub fn deadline_hours_for(&self, severity: &str) -> u32 {
        match severity.to_ascii_lowercase().as_str() {
            "blocker" => self.blocker_hours,
            "critical" => self.critical_hours,
            "major" => self.major_hours,
            "minor" => self.minor_hours,
            "info" => self.info_hours,
            _ => self.major_hours,
        }
    }
}

/// One hotspot's review metadata — pure value type. Persisted separately
/// from the rule-finding so SLA state and review actions are auditable.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HotspotReviewState {
    pub hotspot_id: String,
    pub severity: String,
    pub detected_at: u64,    // unix millis
    pub last_status: String, // to-review|acknowledged|fixed|safe
    pub reviewer: Option<String>,
    pub reviewed_at: Option<u64>,
}

impl HotspotReviewState {
    /// Returns true when the hotspot's elapsed time since `detected_at`
    /// exceeds the SLA window for its severity, AND its last status is
    /// still `to-review`. Reviewed hotspots (acknowledged/fixed/safe) are
    /// never in breach.
    pub fn is_breached(&self, policy: &HotspotSlaPolicy, now_unix_millis: u64) -> bool {
        if self.last_status != "to-review" {
            return false;
        }
        let deadline_hours = policy.deadline_hours_for(&self.severity);
        let deadline_millis = u64::from(deadline_hours) * 60 * 60 * 1000;
        now_unix_millis.saturating_sub(self.detected_at) > deadline_millis
    }

    /// Time remaining (positive) or overrun (negative) in milliseconds.
    pub fn time_remaining_millis(&self, policy: &HotspotSlaPolicy, now_unix_millis: u64) -> i64 {
        let deadline_hours = policy.deadline_hours_for(&self.severity);
        let deadline_millis =
            i64::try_from(u64::from(deadline_hours) * 60 * 60 * 1000).unwrap_or(i64::MAX);
        let elapsed = i64::try_from(now_unix_millis.saturating_sub(self.detected_at)).unwrap_or(0);
        deadline_millis - elapsed
    }
}

/// Per-project review-rate measure (0.0–1.0). Computed on demand by the
/// `/api/hotspots/review-rate` endpoint.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ReviewRate {
    pub project_key: String,
    pub total: usize,
    pub reviewed: usize,
    pub rate: f32,
}

pub fn review_rate(project_key: impl Into<String>, hotspots: &[HotspotReviewState]) -> ReviewRate {
    let total = hotspots.len();
    let reviewed = hotspots
        .iter()
        .filter(|h| h.last_status != "to-review")
        .count();
    let rate = if total == 0 {
        1.0
    } else {
        reviewed as f32 / total as f32
    };
    ReviewRate {
        project_key: project_key.into(),
        total,
        reviewed,
        rate,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn to_review(severity: &str, detected_hours_ago: u64) -> HotspotReviewState {
        let now = 1_700_000_000_000u64;
        HotspotReviewState {
            hotspot_id: "h1".to_string(),
            severity: severity.to_string(),
            detected_at: now - detected_hours_ago * 60 * 60 * 1000,
            last_status: "to-review".to_string(),
            reviewer: None,
            reviewed_at: None,
        }
    }

    #[test]
    fn fresh_blocker_is_not_in_breach() {
        let h = to_review("blocker", 1);
        assert!(!h.is_breached(&HotspotSlaPolicy::default(), 1_700_000_000_000));
    }

    #[test]
    fn stale_blocker_is_in_breach_after_24h() {
        let h = to_review("blocker", 48);
        assert!(h.is_breached(&HotspotSlaPolicy::default(), 1_700_000_000_000));
    }

    #[test]
    fn critical_window_is_72h() {
        let policy = HotspotSlaPolicy::default();
        let h_72 = to_review("critical", 72);
        let h_73 = to_review("critical", 73);
        let now = 1_700_000_000_000u64;
        assert!(!h_72.is_breached(&policy, now));
        assert!(h_73.is_breached(&policy, now));
    }

    #[test]
    fn reviewed_hotspot_is_never_in_breach_even_if_old() {
        let mut h = to_review("blocker", 1000);
        h.last_status = "fixed".to_string();
        assert!(!h.is_breached(&HotspotSlaPolicy::default(), 1_700_000_000_000));
    }

    #[test]
    fn time_remaining_millis_is_positive_before_deadline_negative_after() {
        let policy = HotspotSlaPolicy::default();
        let now = 1_700_000_000_000u64;
        let fresh = to_review("critical", 1);
        let r = fresh.time_remaining_millis(&policy, now);
        assert!(r > 0, "fresh should have positive time remaining, got {r}");

        let stale = to_review("critical", 100);
        let r = stale.time_remaining_millis(&policy, now);
        assert!(r < 0, "stale should have negative time remaining, got {r}");
    }

    #[test]
    fn review_rate_counts_reviewed_vs_total() {
        let mut hs = vec![to_review("blocker", 1), to_review("critical", 1)];
        hs[1].last_status = "fixed".to_string();
        let r = review_rate("yunq", &hs);
        assert_eq!(r.total, 2);
        assert_eq!(r.reviewed, 1);
        assert!((r.rate - 0.5).abs() < 1e-6);
    }

    #[test]
    fn review_rate_is_one_when_no_hotspots() {
        let r = review_rate("yunq", &[]);
        assert_eq!(r.total, 0);
        assert!((r.rate - 1.0).abs() < 1e-6);
    }

    #[test]
    fn unknown_severity_falls_back_to_major_window() {
        let policy = HotspotSlaPolicy::default();
        assert_eq!(policy.deadline_hours_for("mystery"), policy.major_hours);
    }
}
