use yunq_ast::{AstNode, LanguageIdentifier, SourceFile, Span};
use yunq_profiles::{default_impact, IssueType, RuleId, Severity, SoftwareQualityImpact};

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

    /// The classic classification: which of Bug/Vulnerability/CodeSmell
    /// this rule's findings are. Defaults to `CodeSmell`, the
    /// common case — override for rules that detect a Bug or Vulnerability.
    fn issue_type(&self) -> IssueType {
        IssueType::CodeSmell
    }

    /// MQR software-quality impacts (reliability/security/maintainability ×
    /// severity) this rule's findings carry, alongside [`Rule::issue_type`] —
    /// every issue is classified both ways at once rather than one or the
    /// other. Defaults to the single impact `default_impact` derives from
    /// `issue_type` and `default_severity`; override for rules that affect
    /// more than one quality (e.g. a vulnerability that's also a
    /// reliability risk).
    fn software_quality_impacts(&self) -> Vec<SoftwareQualityImpact> {
        vec![default_impact(self.issue_type(), self.default_severity())]
    }

    fn check(&self, file: &SourceFile, ast: &AstNode) -> Vec<Finding>;
}

/// Extension point for whole-program analyses that need every file's AST at
/// once (cross-file taint, dependency rules, …). Same plugin model as
/// [`Rule`], run as a dedicated cross-file phase after per-file analysis.
pub trait CrossFileRule: Send + Sync {
    fn id(&self) -> &RuleId;

    fn default_severity(&self) -> Severity;

    fn remediation_effort_minutes(&self) -> u32 {
        10
    }

    fn metadata(&self) -> RuleMetadata {
        RuleMetadata::default()
    }

    /// See [`Rule::issue_type`].
    fn issue_type(&self) -> IssueType {
        IssueType::CodeSmell
    }

    /// See [`Rule::software_quality_impacts`].
    fn software_quality_impacts(&self) -> Vec<SoftwareQualityImpact> {
        vec![default_impact(self.issue_type(), self.default_severity())]
    }

    /// Findings are reported against an index into `files`.
    fn check(&self, files: &[(SourceFile, AstNode)]) -> Vec<(usize, Finding)>;
}
