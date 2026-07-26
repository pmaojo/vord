//! Core domain for the yunq AI Remediation Agent.
//!
//! Provides the provider-agnostic `LlmProvider` port, `FixPrompt` / `FixProposal`
//! domain entities, and the verify-before-suggest `RemediationEngine` loop that
//! guarantees proposed LLM fixes resolve targeted issues without introducing regressions.

pub mod ai_pr_gateway;

use std::future::Future;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use yunq_ast::{LanguageIdentifier, SourceFile};
use yunq_rules_engine::{AnalyzerService, HotspotStorage, Issue, IssueStorage, MetricsTracker};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FixPrompt {
    pub rule_id: String,
    pub issue_message: String,
    pub file_path: PathBuf,
    pub start_line: usize,
    pub end_line: usize,
    pub source_snippet: String,
    pub full_source: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct FixProposal {
    pub file_path: PathBuf,
    pub explanation: String,
    pub original_snippet: String,
    pub replacement_snippet: String,
}

#[derive(Debug, thiserror::Error)]
pub enum LlmError {
    #[error("LLM API request failed: {0}")]
    ApiFailure(String),
    #[error("LLM output could not be parsed into a valid fix proposal: {0}")]
    InvalidOutput(String),
}

#[derive(Debug, thiserror::Error)]
pub enum RemediationError {
    #[error("Sandbox I/O error: {0}")]
    SandboxError(String),
    #[error("LLM Provider error: {0}")]
    Llm(#[from] LlmError),
    #[error("Analysis error during verification: {0}")]
    AnalysisError(String),
}

/// Outbound port: generates fix proposals for static analysis findings.
/// Implementations live in `infra/llm` (OpenAI-compatible, Anthropic, Mock).
pub trait LlmProvider: Send + Sync {
    fn generate_fix(
        &self,
        prompt: &FixPrompt,
    ) -> impl Future<Output = Result<FixProposal, LlmError>> + Send;
}

/// Outbound port: applies fix proposals in an isolated filesystem or worktree.
pub trait Sandbox: Send + Sync {
    fn apply_proposal(&self, proposal: &FixProposal) -> Result<(), RemediationError>;
    /// Read the modified source from the sandbox, never from the caller's checkout.
    fn read_source(&self, file_path: &Path) -> Result<String, RemediationError>;
    fn rollback(&self) -> Result<(), RemediationError>;
}

/// Verdict from the remediation verification loop.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum RemediationVerdict {
    Accepted { proposal: FixProposal },
    Rejected { reason: String },
}

/// Builds the LLM prompt for `issue`: the target snippet (its span, clamped
/// to the file's actual line count) plus the full source for context.
fn build_fix_prompt(issue: &Issue, file_path: &Path, source_code: &str) -> FixPrompt {
    let lines: Vec<&str> = source_code.lines().collect();
    let start_line_usize = issue.span().start_line as usize;
    let end_line_usize = issue.span().end_line as usize;
    let start_idx = start_line_usize.saturating_sub(1);
    let end_idx = end_line_usize.min(lines.len());
    let snippet = lines[start_idx..end_idx].join("\n");

    FixPrompt {
        rule_id: issue.rule().to_string(),
        issue_message: issue.message().to_string(),
        file_path: file_path.to_path_buf(),
        start_line: start_line_usize,
        end_line: end_line_usize,
        source_snippet: snippet,
        full_source: source_code.to_string(),
    }
}

pub struct RemediationEngine<P, S> {
    provider: P,
    sandbox: S,
}

impl<P: LlmProvider, S: Sandbox> RemediationEngine<P, S> {
    pub fn new(provider: P, sandbox: S) -> Self {
        Self { provider, sandbox }
    }

    /// Reads the modified source back from the sandbox after applying a
    /// proposal, rolling back on any read failure.
    fn reread_modified_source(&self, file_path: &Path) -> Result<String, RemediationError> {
        self.sandbox.read_source(file_path).map_err(|e| {
            let _ = self.sandbox.rollback();
            RemediationError::SandboxError(e.to_string())
        })
    }

    /// Accepts the fix unless the target rule still fires or any other
    /// issue was introduced, rolling back the sandbox on rejection.
    fn decide_verdict(
        &self,
        issue: &Issue,
        report: &yunq_rules_engine::AnalysisReport,
        proposal: FixProposal,
    ) -> RemediationVerdict {
        let target_rule_still_fails = report.issues().iter().any(|i| i.rule() == issue.rule());
        if target_rule_still_fails {
            let _ = self.sandbox.rollback();
            return RemediationVerdict::Rejected {
                reason: format!("Target issue {} still detected after applying fix", issue.rule()),
            };
        }

        let regressions = report.issues().len();
        if regressions > 0 {
            let _ = self.sandbox.rollback();
            return RemediationVerdict::Rejected {
                reason: format!("Fix introduced {regressions} new regression issues"),
            };
        }

        RemediationVerdict::Accepted { proposal }
    }

    /// Evaluates a proposed fix: generates fix with LLM provider, applies to sandbox,
    /// re-runs analyzer, and accepts only if original issue is gone with 0 new issues.
    pub async fn attempt_remediation<IS: IssueStorage + HotspotStorage, MT: MetricsTracker>(
        &self,
        issue: &Issue,
        file_path: &Path,
        source_code: &str,
        analyzer: &AnalyzerService<IS, MT>,
    ) -> Result<RemediationVerdict, RemediationError> {
        let prompt = build_fix_prompt(issue, file_path, source_code);
        let proposal = self.provider.generate_fix(&prompt).await?;
        self.sandbox.apply_proposal(&proposal)?;

        // Read the modified source from the isolated worktree after applying the fix.
        let modified_source = self.reread_modified_source(file_path)?;

        let ext = file_path.extension().and_then(|e| e.to_str()).unwrap_or("");
        let language = LanguageIdentifier::from_extension(ext)
            .unwrap_or_else(LanguageIdentifier::rust);

        let rel_path = file_path.to_string_lossy().trim_start_matches('/').to_string();
        let file_input = match SourceFile::new(rel_path, modified_source, language) {
            Ok(f) => f,
            Err(e) => {
                let _ = self.sandbox.rollback();
                return Err(RemediationError::AnalysisError(format!("Invalid file path: {e}")));
            }
        };

        let report = analyzer
            .analyze_files(&[file_input])
            .await
            .map_err(|e| RemediationError::AnalysisError(e.to_string()))?;

        Ok(self.decide_verdict(issue, &report, proposal))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use yunq_ast::{AstNode, LanguageIdentifier, NodeKind, Span};
    use yunq_rules_engine::{
        AstParser, Finding, ParseError, QualityProfile, Rule, RuleId, RuleMetadata, Severity,
        StorageError,
    };

    use super::*;

    /// Fires whenever `marker` appears anywhere in the file's source text —
    /// good enough to drive the verify-before-suggest loop without needing
    /// a real language grammar.
    struct MarkerRule {
        id: RuleId,
        marker: &'static str,
    }

    impl Rule for MarkerRule {
        fn id(&self) -> &RuleId {
            &self.id
        }

        fn applies_to(&self, _language: &LanguageIdentifier) -> bool {
            true
        }

        fn default_severity(&self) -> Severity {
            Severity::Major
        }

        fn metadata(&self) -> RuleMetadata {
            RuleMetadata {
                description: "test marker rule".into(),
                tags: vec![],
                cwe: None,
                produces_hotspots: false,
            }
        }

        fn check(&self, file: &yunq_ast::SourceFile, _ast: &AstNode) -> Vec<Finding> {
            if file.content().contains(self.marker) {
                vec![Finding::new(format!("found {}", self.marker), Span::new(1, 1, 1, 1))]
            } else {
                vec![]
            }
        }
    }

    /// No-op parser: wraps the whole file in a single leaf node, since these
    /// tests only need `Rule::check` to see the raw source text.
    struct IdentityParser;

    impl AstParser for IdentityParser {
        fn language(&self) -> LanguageIdentifier {
            LanguageIdentifier::rust()
        }

        fn parse(&self, file: &yunq_ast::SourceFile) -> Result<AstNode, ParseError> {
            Ok(AstNode::new(NodeKind::Other("root".into()), Span::new(1, 1, 1, 1), file.content().to_string(), vec![]))
        }
    }

    #[derive(Default)]
    struct NoopStorage;

    impl yunq_rules_engine::IssueStorage for NoopStorage {
        async fn save_issues(
            &self,
            _issues: &[Issue],
            _scope: yunq_rules_engine::IssueScope,
        ) -> Result<(), StorageError> {
            Ok(())
        }
    }

    impl yunq_rules_engine::HotspotStorage for NoopStorage {
        async fn save_hotspots(
            &self,
            _hotspots: &[yunq_rules_engine::Hotspot],
            _scope: yunq_rules_engine::IssueScope,
        ) -> Result<(), StorageError> {
            Ok(())
        }
    }

    #[derive(Default)]
    struct NoopMetrics;

    impl yunq_rules_engine::MetricsTracker for NoopMetrics {
        async fn record(&self, _metrics: &yunq_rules_engine::Metrics) -> Result<(), StorageError> {
            Ok(())
        }
    }

    fn analyzer_with_marker_rules(
        rules: Vec<(&'static str, Severity)>,
    ) -> AnalyzerService<NoopStorage, NoopMetrics> {
        let activations: Vec<(RuleId, Severity)> = rules
            .iter()
            .map(|(marker, severity)| (RuleId::new(&format!("test:{marker}")).unwrap(), *severity))
            .collect();
        let profile = QualityProfile::from_activations("test", activations);
        let mut service = AnalyzerService::new(profile, NoopStorage, NoopMetrics)
            .register_parser(Box::new(IdentityParser));
        for (marker, _) in rules {
            service = service.register_rule(Box::new(MarkerRule {
                id: RuleId::new(&format!("test:{marker}")).unwrap(),
                marker,
            }));
        }
        service
    }

    fn issue_for(rule: &str, file: &str) -> Issue {
        Issue::new(RuleId::new(rule).unwrap(), Severity::Major, "test issue", file, Span::new(1, 1, 1, 1))
    }

    /// Fake `Sandbox`: an in-memory single file, with the same exact-once
    /// snippet-replace semantics as the real filesystem adapters, so it
    /// exercises `attempt_remediation`'s actual apply/read/rollback calls
    /// rather than trivially no-opping them.
    struct FakeSandbox {
        original: String,
        current: Mutex<String>,
    }

    impl FakeSandbox {
        fn new(content: impl Into<String>) -> Self {
            let content = content.into();
            Self { original: content.clone(), current: Mutex::new(content) }
        }
    }

    impl Sandbox for FakeSandbox {
        fn apply_proposal(&self, proposal: &FixProposal) -> Result<(), RemediationError> {
            let mut current = self.current.lock().unwrap();
            *current = current.replacen(&proposal.original_snippet, &proposal.replacement_snippet, 1);
            Ok(())
        }

        fn read_source(&self, _file_path: &Path) -> Result<String, RemediationError> {
            Ok(self.current.lock().unwrap().clone())
        }

        fn rollback(&self) -> Result<(), RemediationError> {
            *self.current.lock().unwrap() = self.original.clone();
            Ok(())
        }
    }

    struct FakeLlmProvider {
        proposal: FixProposal,
    }

    impl LlmProvider for FakeLlmProvider {
        async fn generate_fix(&self, _prompt: &FixPrompt) -> Result<FixProposal, LlmError> {
            Ok(self.proposal.clone())
        }
    }

    #[tokio::test]
    async fn accepts_a_fix_that_resolves_the_issue_without_regressions() {
        let analyzer = analyzer_with_marker_rules(vec![("dangerous", Severity::Major)]);
        let issue = issue_for("test:dangerous", "src/lib.rs");
        let source = "fn run() {\n    dangerous_call();\n}\n";
        let sandbox = FakeSandbox::new(source);
        let provider = FakeLlmProvider {
            proposal: FixProposal {
                file_path: PathBuf::from("src/lib.rs"),
                explanation: "removed the dangerous call".to_string(),
                original_snippet: "dangerous_call();".to_string(),
                replacement_snippet: "safe_call();".to_string(),
            },
        };
        let engine = RemediationEngine::new(provider, sandbox);

        let verdict = engine
            .attempt_remediation(&issue, Path::new("src/lib.rs"), source, &analyzer)
            .await
            .unwrap();

        match verdict {
            RemediationVerdict::Accepted { proposal } => {
                assert_eq!(proposal.replacement_snippet, "safe_call();");
            }
            RemediationVerdict::Rejected { reason } => panic!("expected acceptance, got: {reason}"),
        }
    }

    #[tokio::test]
    async fn rejects_and_rolls_back_when_the_original_issue_persists() {
        let analyzer = analyzer_with_marker_rules(vec![("dangerous", Severity::Major)]);
        let issue = issue_for("test:dangerous", "src/lib.rs");
        let source = "fn run() {\n    dangerous_call();\n}\n";
        let sandbox = FakeSandbox::new(source);
        // The "fix" is a no-op rename that still contains the marker text.
        let provider = FakeLlmProvider {
            proposal: FixProposal {
                file_path: PathBuf::from("src/lib.rs"),
                explanation: "no-op".to_string(),
                original_snippet: "dangerous_call();".to_string(),
                replacement_snippet: "dangerous_call(/* still bad */);".to_string(),
            },
        };
        let engine = RemediationEngine::new(provider, sandbox);

        let verdict = engine
            .attempt_remediation(&issue, Path::new("src/lib.rs"), source, &analyzer)
            .await
            .unwrap();

        match verdict {
            RemediationVerdict::Rejected { reason } => {
                assert!(reason.contains("still detected"), "unexpected reason: {reason}");
            }
            RemediationVerdict::Accepted { .. } => panic!("expected rejection"),
        }
        // Verified end-to-end: the sandbox itself rolled back to the original.
        assert_eq!(
            engine.sandbox.read_source(Path::new("src/lib.rs")).unwrap(),
            source
        );
    }

    #[tokio::test]
    async fn rejects_a_fix_that_introduces_a_regression() {
        let analyzer = analyzer_with_marker_rules(vec![
            ("dangerous", Severity::Major),
            ("leftover", Severity::Minor),
        ]);
        let issue = issue_for("test:dangerous", "src/lib.rs");
        let source = "fn run() {\n    dangerous_call();\n}\n";
        let sandbox = FakeSandbox::new(source);
        // Resolves the target issue but introduces a different one.
        let provider = FakeLlmProvider {
            proposal: FixProposal {
                file_path: PathBuf::from("src/lib.rs"),
                explanation: "swapped one problem for another".to_string(),
                original_snippet: "dangerous_call();".to_string(),
                replacement_snippet: "leftover_call();".to_string(),
            },
        };
        let engine = RemediationEngine::new(provider, sandbox);

        let verdict = engine
            .attempt_remediation(&issue, Path::new("src/lib.rs"), source, &analyzer)
            .await
            .unwrap();

        match verdict {
            RemediationVerdict::Rejected { reason } => {
                assert!(reason.contains("regression"), "unexpected reason: {reason}");
            }
            RemediationVerdict::Accepted { .. } => panic!("expected rejection"),
        }
    }
}
