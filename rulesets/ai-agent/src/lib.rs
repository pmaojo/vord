//! Detections aimed squarely at AI-generated and AI-agent code: risk classes
//! the industry's own research on "vibe coding" and agentic pipelines calls
//! out as uncovered by generic SAST (Semgrep, CodeQL, Bandit) — none of them
//! model an LLM's own output as a taint source, or a `@tool`/MCP boundary.
//! This crate is where that category of check lives, starting with treating
//! an LLM SDK response as untrusted input reaching an execution sink.

mod llm_output_injection;

pub use llm_output_injection::LlmOutputInjectionRule;

use yunq_rules_engine::Rule;

/// Every rule in this ruleset, for composition roots.
pub fn all_rules() -> Vec<Box<dyn Rule>> {
    vec![Box::new(LlmOutputInjectionRule::new())]
}
