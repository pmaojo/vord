//! Shared request/response plumbing used by every chat-style `LlmProvider`
//! adapter: the fix-proposal system prompt, the user prompt template, and
//! the JSON parsing (with markdown-fence tolerance) that turns a model's
//! raw text reply into a `FixProposal`.

use serde::Deserialize;
use std::path::Path;
use yunq_remediation::{FixPrompt, FixProposal, LlmError};

pub(crate) const SYSTEM_PROMPT: &str = "You are yunq's automated Remediation Agent. Your job is to fix code analysis findings accurately.\n\
    Return ONLY a valid JSON object matching this exact schema, with no markdown code blocks:\n\
    {\n  \"explanation\": \"short rationale\",\n  \"original_snippet\": \"exact lines to replace\",\n  \"replacement_snippet\": \"new lines\"\n}";

pub(crate) fn user_prompt(prompt: &FixPrompt) -> String {
    format!(
        "File: {}\nRule Violated: {}\nIssue Message: {}\nLines: {}-{}\n\nOriginal Code Snippet:\n```\n{}\n```\n\nFull Source Context:\n```\n{}\n```",
        prompt.file_path.display(),
        prompt.rule_id,
        prompt.issue_message,
        prompt.start_line,
        prompt.end_line,
        prompt.source_snippet,
        prompt.full_source
    )
}

/// Strips a leading/trailing ```` ``` ```` or ```` ```json ```` markdown code
/// fence, in case the model wrapped its JSON in one despite being asked not
/// to.
pub(crate) fn strip_code_fence(content: &str) -> &str {
    content
        .strip_prefix("```json")
        .or_else(|| content.strip_prefix("```"))
        .unwrap_or(content)
        .strip_suffix("```")
        .unwrap_or(content)
        .trim()
}

#[derive(Deserialize)]
struct FixProposalJson {
    explanation: String,
    original_snippet: String,
    replacement_snippet: String,
}

/// Parses a model's raw text reply into a `FixProposal`, tolerating a
/// markdown code fence around the JSON body.
pub(crate) fn parse_fix_proposal(content: &str, file_path: &Path) -> Result<FixProposal, LlmError> {
    let clean_json = strip_code_fence(content);
    let parsed: FixProposalJson = serde_json::from_str(clean_json).map_err(|e| {
        LlmError::InvalidOutput(format!("JSON fix proposal schema mismatch: {e}. Raw content: {content}"))
    })?;

    Ok(FixProposal {
        file_path: file_path.to_path_buf(),
        explanation: parsed.explanation,
        original_snippet: parsed.original_snippet,
        replacement_snippet: parsed.replacement_snippet,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strip_code_fence_removes_plain_fence() {
        assert_eq!(strip_code_fence("```\n{\"a\":1}\n```"), "{\"a\":1}");
    }

    #[test]
    fn strip_code_fence_removes_json_fence() {
        assert_eq!(strip_code_fence("```json\n{\"a\":1}\n```"), "{\"a\":1}");
    }

    #[test]
    fn strip_code_fence_leaves_unfenced_content_untouched() {
        assert_eq!(strip_code_fence("{\"a\":1}"), "{\"a\":1}");
    }

    #[test]
    fn parse_fix_proposal_tolerates_fence() {
        let content = "```json\n{\"explanation\":\"e\",\"original_snippet\":\"o\",\"replacement_snippet\":\"r\"}\n```";
        let proposal = parse_fix_proposal(content, Path::new("src/lib.rs")).unwrap();
        assert_eq!(proposal.explanation, "e");
        assert_eq!(proposal.original_snippet, "o");
        assert_eq!(proposal.replacement_snippet, "r");
    }

    #[test]
    fn parse_fix_proposal_rejects_malformed_json() {
        let err = parse_fix_proposal("not json", Path::new("src/lib.rs")).unwrap_err();
        assert!(matches!(err, LlmError::InvalidOutput(_)));
    }
}
