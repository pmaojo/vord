use yunq_ast::{AstNode, LanguageIdentifier, SourceFile, Span};
use yunq_profiles::{RuleId, Severity};

/// Whether a detection is a definite problem (issue) or security-sensitive
/// code that needs human review (hotspot).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FindingKind {
    Issue,
    Hotspot,
}

/// A raw detection produced by a rule. The service turns findings into
/// `Issue`s or `Hotspot`s, applying the severity decided by the active
/// quality profile — rules detect, the profile judges.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Finding {
    pub message: String,
    pub span: Span,
    pub kind: FindingKind,
}

impl Finding {
    pub fn new(message: impl Into<String>, span: Span) -> Self {
        Self { message: message.into(), span, kind: FindingKind::Issue }
    }

    pub fn hotspot(message: impl Into<String>, span: Span) -> Self {
        Self { message: message.into(), span, kind: FindingKind::Hotspot }
    }
}

/// Descriptive metadata for a rule: what it detects, how it maps to
/// security standards, and how it is categorized. Consumed by the Rules API
/// and the frontend rule browser.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RuleMetadata {
    pub description: String,
    pub tags: Vec<String>,
    /// CWE id this rule maps to, if any (e.g. 798 for hardcoded credentials).
    pub cwe: Option<u32>,
    /// Whether findings are security hotspots rather than issues.
    pub produces_hotspots: bool,
}

/// The Open/Closed extension point. Adding a check to the platform means
/// implementing this trait in a ruleset crate and registering it at a
/// composition root — the engine itself never changes.
pub trait Rule: Send + Sync {
    fn id(&self) -> &RuleId;

    /// Which languages this rule can analyze.
    fn applies_to(&self, language: &LanguageIdentifier) -> bool;

    /// Severity used when the profile activates the rule without an override.
    fn default_severity(&self) -> Severity;

    /// Estimated minutes to remediate one finding of this rule (technical
    /// debt model). Override where the default is unrealistic.
    fn remediation_effort_minutes(&self) -> u32 {
        10
    }

    /// Descriptive metadata for catalogs and the Rules API.
    fn metadata(&self) -> RuleMetadata {
        RuleMetadata::default()
    }

    fn check(&self, file: &SourceFile, ast: &AstNode) -> Vec<Finding>;
}
