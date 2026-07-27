//! Email notification port + templates. ROADMAP §Phase 4 — "email
//! notifications per user subscription".
//!
//! Skeleton: the EmailTransport trait, the template registry, and the
//! subscription record are in place; SMTP/SES adapter, HTTP surface, and
//! the trigger paths from analysis-finished / gate-changed events land
//! in following iterations.

#![allow(dead_code)]

use serde::{Deserialize, Serialize};

/// One subscription: a user opted into a specific event class.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmailSubscription {
    pub user_email: String,
    pub event: NotificationEvent,
    pub enabled: bool,
}

/// What triggers an email.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NotificationEvent {
    AnalysisFinished,
    GateChanged,
    IssueAssignedToMe,
    HotspotAssignedToMe,
    QualityProfileUpdated,
}

/// One rendered email, ready for transport.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmailMessage {
    pub to: String,
    pub subject: String,
    pub body_text: String,
    pub body_html: Option<String>,
    pub event: NotificationEvent,
}

/// The transport port — every adapter (SMTP, SES, Mailgun, console-log
/// for tests) implements this. Object-safe so callers can hold
/// `Arc<dyn EmailTransport>`.
pub trait EmailTransport: Send + Sync {
    fn send(&self, message: &EmailMessage) -> Result<(), EmailError>;
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum EmailError {
    /// Provider rejected the message (4xx-equivalent).
    Rejected(String),
    /// Network / provider unavailable (5xx-equivalent).
    Unavailable(String),
    /// Malformed recipient address.
    BadAddress(String),
}

impl std::fmt::Display for EmailError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Rejected(s) => write!(f, "email rejected: {s}"),
            Self::Unavailable(s) => write!(f, "email provider unavailable: {s}"),
            Self::BadAddress(s) => write!(f, "bad email address: {s}"),
        }
    }
}

impl std::error::Error for EmailError {}

/// Pure template helper — render the subject + body for a single event.
/// Lives outside the transport trait so it can be tested without any I/O.
pub fn render(event: NotificationEvent, ctx: &TemplateContext) -> EmailMessage {
    match event {
        NotificationEvent::AnalysisFinished => EmailMessage {
            to: ctx.recipient.clone(),
            subject: format!("[yunq] Analysis finished for {}", ctx.project_key),
            body_text: format!(
                "Analysis for project {} completed.\nNew issues: {}\nQuality gate: {}",
                ctx.project_key, ctx.new_issues, ctx.gate_status
            ),
            body_html: Some(format!(
                "<p>Analysis for project <b>{}</b> completed.</p><ul><li>New issues: {}</li><li>Quality gate: {}</li></ul>",
                ctx.project_key, ctx.new_issues, ctx.gate_status
            )),
            event,
        },
        NotificationEvent::GateChanged => EmailMessage {
            to: ctx.recipient.clone(),
            subject: format!(
                "[yunq] Quality gate {} for {}",
                ctx.gate_status, ctx.project_key
            ),
            body_text: format!(
                "Quality gate for {} is now {}.",
                ctx.project_key, ctx.gate_status
            ),
            body_html: Some(format!(
                "<p>Quality gate for <b>{}</b> is now <b>{}</b>.</p>",
                ctx.project_key, ctx.gate_status
            )),
            event,
        },
        NotificationEvent::IssueAssignedToMe => EmailMessage {
            to: ctx.recipient.clone(),
            subject: format!("[yunq] Issue {} assigned to you", ctx.issue_key),
            body_text: format!("Issue {} has been assigned to you.", ctx.issue_key),
            body_html: None,
            event,
        },
        NotificationEvent::HotspotAssignedToMe => EmailMessage {
            to: ctx.recipient.clone(),
            subject: format!("[yunq] Hotspot {} assigned to you", ctx.issue_key),
            body_text: format!("Hotspot {} has been assigned to you.", ctx.issue_key),
            body_html: None,
            event,
        },
        NotificationEvent::QualityProfileUpdated => EmailMessage {
            to: ctx.recipient.clone(),
            subject: format!("[yunq] Quality profile updated: {}", ctx.profile_name),
            body_text: format!(
                "Quality profile {} has been updated ({} activations changed).",
                ctx.profile_name, ctx.profile_changes
            ),
            body_html: None,
            event,
        },
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TemplateContext {
    pub recipient: String,
    pub project_key: String,
    pub issue_key: String,
    pub profile_name: String,
    pub profile_changes: i64,
    pub new_issues: i64,
    pub gate_status: String,
}

/// Filter a subscription list to only those enabled for `event`.
pub fn subscribed_to(
    subscriptions: &[EmailSubscription],
    event: NotificationEvent,
) -> impl Iterator<Item = &str> {
    subscriptions
        .iter()
        .filter(move |s| s.enabled && s.event == event)
        .map(|s| s.user_email.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn analysis_finished_template_fills_project_and_counts() {
        let m = render(
            NotificationEvent::AnalysisFinished,
            &TemplateContext {
                recipient: "alice@example.com".to_string(),
                project_key: "yunq".to_string(),
                new_issues: 3,
                gate_status: "passed".to_string(),
                ..Default::default()
            },
        );
        assert!(m.subject.contains("yunq"));
        assert!(m.subject.contains("Analysis finished"));
        assert!(m.body_text.contains("3"));
        assert!(m.body_html.unwrap().contains("<b>yunq</b>"));
        assert_eq!(m.event, NotificationEvent::AnalysisFinished);
    }

    #[test]
    fn gate_changed_template_includes_status() {
        let m = render(
            NotificationEvent::GateChanged,
            &TemplateContext {
                recipient: "bob@example.com".to_string(),
                project_key: "yunq".to_string(),
                gate_status: "failed".to_string(),
                ..Default::default()
            },
        );
        assert!(m.subject.contains("failed"));
        assert!(m.body_text.contains("now failed"));
    }

    #[test]
    fn issue_assigned_template_uses_issue_key() {
        let m = render(
            NotificationEvent::IssueAssignedToMe,
            &TemplateContext {
                recipient: "c@example.com".to_string(),
                issue_key: "YQ-42".to_string(),
                ..Default::default()
            },
        );
        assert!(m.subject.contains("YQ-42"));
        assert!(m.body_text.contains("YQ-42"));
        assert!(m.body_html.is_none()); // simple events get plain text only
    }

    #[test]
    fn subscribed_to_filters_disabled_subscriptions() {
        let subs = vec![
            EmailSubscription {
                user_email: "a@x".to_string(),
                event: NotificationEvent::AnalysisFinished,
                enabled: true,
            },
            EmailSubscription {
                user_email: "b@x".to_string(),
                event: NotificationEvent::AnalysisFinished,
                enabled: false,
            },
            EmailSubscription {
                user_email: "c@x".to_string(),
                event: NotificationEvent::GateChanged,
                enabled: true,
            },
        ];
        let got: Vec<&str> = subscribed_to(&subs, NotificationEvent::AnalysisFinished).collect();
        assert_eq!(got, vec!["a@x"]);
    }

    #[test]
    fn email_error_display_does_not_crash_on_empty_message() {
        let e = EmailError::BadAddress(String::new());
        assert_eq!(e.to_string(), "bad email address: ");
    }

    #[test]
    fn event_serializes_snake_case() {
        assert_eq!(
            serde_json::to_string(&NotificationEvent::AnalysisFinished).unwrap(),
            "\"analysis_finished\""
        );
        assert_eq!(
            serde_json::to_string(&NotificationEvent::QualityProfileUpdated).unwrap(),
            "\"quality_profile_updated\""
        );
    }
}
