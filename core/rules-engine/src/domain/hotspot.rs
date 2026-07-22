use std::fmt;
use yunq_ast::Span;
use yunq_profiles::RuleId;

/// Review state of a security hotspot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HotspotStatus {
    ToReview,
    Acknowledged,
    Fixed,
    Safe,
}

impl HotspotStatus {
    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "to-review" => Some(HotspotStatus::ToReview),
            "acknowledged" => Some(HotspotStatus::Acknowledged),
            "fixed" => Some(HotspotStatus::Fixed),
            "safe" => Some(HotspotStatus::Safe),
            _ => None,
        }
    }
}

impl fmt::Display for HotspotStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            HotspotStatus::ToReview => "to-review",
            HotspotStatus::Acknowledged => "acknowledged",
            HotspotStatus::Fixed => "fixed",
            HotspotStatus::Safe => "safe",
        })
    }
}

/// A hotspot as persisted by a storage adapter, carrying its storage identity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredHotspot {
    pub id: i64,
    pub hotspot: Hotspot,
}

/// Security-sensitive code requiring human review.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Hotspot {
    rule: RuleId,
    message: String,
    file: String,
    span: Span,
    status: HotspotStatus,
}

impl Hotspot {
    pub fn new(rule: RuleId, message: impl Into<String>, file: impl Into<String>, span: Span) -> Self {
        Self {
            rule,
            message: message.into(),
            file: file.into(),
            span,
            status: HotspotStatus::ToReview,
        }
    }

    pub fn restore(
        rule: RuleId,
        message: impl Into<String>,
        file: impl Into<String>,
        span: Span,
        status: HotspotStatus,
    ) -> Self {
        Self { rule, message: message.into(), file: file.into(), span, status }
    }

    pub fn rule(&self) -> &RuleId {
        &self.rule
    }

    pub fn message(&self) -> &str {
        &self.message
    }

    pub fn file(&self) -> &str {
        &self.file
    }

    pub fn span(&self) -> Span {
        self.span
    }

    pub fn status(&self) -> HotspotStatus {
        self.status
    }

    pub fn review(&mut self, status: HotspotStatus) {
        self.status = status;
    }
}
