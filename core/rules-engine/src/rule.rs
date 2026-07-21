use yunq_ast::{AstNode, LanguageIdentifier, SourceFile, Span};
use yunq_profiles::{RuleId, Severity};

/// A raw detection produced by a rule. The service turns findings into
/// `Issue`s, applying the severity decided by the active quality profile —
/// rules detect, the profile judges.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Finding {
    pub message: String,
    pub span: Span,
}

impl Finding {
    pub fn new(message: impl Into<String>, span: Span) -> Self {
        Self { message: message.into(), span }
    }
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

    fn check(&self, file: &SourceFile, ast: &AstNode) -> Vec<Finding>;
}
