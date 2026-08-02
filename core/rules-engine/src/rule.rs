use vord_ast::{AstNode, LanguageIdentifier, SourceFile, Span};
use vord_profiles::{IssueType, RuleId, Severity, SoftwareQualityImpact, default_impact};

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
        Self {
            message: message.into(),
            span,
            kind: FindingKind::Issue,
        }
    }

    pub fn hotspot(message: impl Into<String>, span: Span) -> Self {
        Self {
            message: message.into(),
            span,
            kind: FindingKind::Hotspot,
        }
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

/// Generates the `struct`/`new`/`Default` cluster every [`Rule`] implementor
/// repeats verbatim — only the type name and the rule id string differ
/// between rules; everything else (the field, the constructor, `Default`
/// delegating to it) is identical in every ruleset crate in this workspace.
///
/// Deliberately stops there: `impl Rule for X { .. }` — `check`, `metadata`,
/// severity, and every other trait method — stays hand-written in each
/// rule's own file, because that is where rules actually differ from one
/// another. Folding `check`'s detection logic into a macro too would trade
/// a real duplication problem (there isn't one there) for an unreadable one
/// (a `macro_rules!` matcher standing in for what should be plain code).
///
/// ```
/// # use vord_rules_engine::{declare_rule_id, Finding, IssueType, Rule, RuleId, Severity};
/// # use vord_ast::{AstNode, LanguageIdentifier, SourceFile};
/// declare_rule_id!(ExampleRule, "example:my-rule");
///
/// impl Rule for ExampleRule {
///     fn id(&self) -> &RuleId { &self.id }
///     fn applies_to(&self, _lang: &LanguageIdentifier) -> bool { true }
///     fn default_severity(&self) -> Severity { Severity::Minor }
///     fn check(&self, _file: &SourceFile, _ast: &AstNode) -> Vec<Finding> { Vec::new() }
/// }
///
/// assert_eq!(ExampleRule::default().id().as_str(), "example:my-rule");
/// ```
#[macro_export]
macro_rules! declare_rule_id {
    ($name:ident, $rule_id:literal) => {
        pub struct $name {
            id: $crate::RuleId,
        }

        impl $name {
            pub fn new() -> Self {
                Self {
                    id: $crate::RuleId::new($rule_id).expect("valid rule id"),
                }
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }
    };
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
