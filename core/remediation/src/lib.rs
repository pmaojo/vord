//! Core domain for the yunq AI Remediation Agent.
//!
//! Provides the provider-agnostic `LlmProvider` port, `FixPrompt` / `FixProposal`
//! domain entities, and the verify-before-suggest `RemediationEngine` loop that
//! guarantees proposed LLM fixes resolve targeted issues without introducing regressions.

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

#[derive(Clone, Debug, Serialize, Deserialize)]
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
    fn rollback(&self) -> Result<(), RemediationError>;
}

/// Verdict from the remediation verification loop.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum RemediationVerdict {
    Accepted { proposal: FixProposal },
    Rejected { reason: String },
}

pub struct RemediationEngine<P, S> {
    provider: P,
    sandbox: S,
}

impl<P: LlmProvider, S: Sandbox> RemediationEngine<P, S> {
    pub fn new(provider: P, sandbox: S) -> Self {
        Self { provider, sandbox }
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
        let lines: Vec<&str> = source_code.lines().collect();
        let start_line_usize = issue.span().start_line as usize;
        let end_line_usize = issue.span().end_line as usize;
        let start_idx = start_line_usize.saturating_sub(1);
        let end_idx = end_line_usize.min(lines.len());
        let snippet = lines[start_idx..end_idx].join("\n");

        let prompt = FixPrompt {
            rule_id: issue.rule().to_string(),
            issue_message: issue.message().to_string(),
            file_path: file_path.to_path_buf(),
            start_line: start_line_usize,
            end_line: end_line_usize,
            source_snippet: snippet,
            full_source: source_code.to_string(),
        };

        let proposal = self.provider.generate_fix(&prompt).await?;
        self.sandbox.apply_proposal(&proposal)?;

        // Read modified source code after fix
        let modified_source = match std::fs::read_to_string(file_path) {
            Ok(s) => s,
            Err(e) => {
                let _ = self.sandbox.rollback();
                return Err(RemediationError::SandboxError(e.to_string()));
            }
        };

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

        // Check if targeted rule still triggers on this file
        let target_rule_still_fails = report.issues().iter().any(|i| i.rule() == issue.rule());
        if target_rule_still_fails {
            let _ = self.sandbox.rollback();
            return Ok(RemediationVerdict::Rejected {
                reason: format!("Target issue {} still detected after applying fix", issue.rule()),
            });
        }

        // Check if any new blocker/critical issues were introduced
        let regressions = report.issues().len();
        if regressions > 0 {
            let _ = self.sandbox.rollback();
            return Ok(RemediationVerdict::Rejected {
                reason: format!("Fix introduced {regressions} new regression issues"),
            });
        }

        Ok(RemediationVerdict::Accepted { proposal })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    pub struct DummySandbox;
    impl Sandbox for DummySandbox {
        fn apply_proposal(&self, _proposal: &FixProposal) -> Result<(), RemediationError> {
            Ok(())
        }
        fn rollback(&self) -> Result<(), RemediationError> {
            Ok(())
        }
    }
}
