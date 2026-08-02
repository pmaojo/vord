//! Taint-based detection of the "trusting the LLM" bug: an agent calls an
//! LLM SDK, reads the assistant's reply out of the response object, and
//! feeds that text straight into a code- or command-execution sink (or a
//! SQL call) without ever treating it as untrusted input. Generic SAST
//! tools don't model an LLM response as a taint source at all — this rule
//! exists specifically to close that gap.
//!
//! Source markers are shaped after the real response types the two
//! dominant SDK families return (see `infra/llm/src/openai_compatible.rs`'s
//! `ChatCompletionResponse { choices: Vec<ChatChoice> }` and
//! `infra/llm/src/anthropic.rs`'s `MessagesResponse { content:
//! Vec<ContentBlock> }` for this codebase's own equivalents): OpenAI-style
//! `choices[0].message.content`, Anthropic-style `content[0].text`, and the
//! generic shape any wrapper around either tends to keep — a variable
//! literally named `message`/`response`/`completion` with a `.content`
//! property.

use vord_ast::{AstNode, LanguageIdentifier, SourceFile};
use vord_rules_engine::{Finding, IssueType, Rule, RuleId, RuleMetadata, Severity};
use vord_taint::{TaintAnalysis, TaintConfig};

pub struct LlmOutputInjectionRule {
    id: RuleId,
    analysis: TaintAnalysis,
}

impl LlmOutputInjectionRule {
    pub fn new() -> Self {
        let config = TaintConfig::new()
            // OpenAI chat completions: `completion.choices[0].message.content`.
            .with_source_marker(".choices[0].message.content")
            // Anthropic messages: `response.content[0].text`.
            .with_source_marker(".content[0].text")
            // Generic shape: a `message`/`response`/`completion` object's
            // `.content` — covers wrapper SDKs and hand-rolled clients that
            // don't match either vendor's exact chain above.
            .with_source_marker("message.content")
            .with_source_marker("response.content")
            .with_source_marker("completion.content")
            .with_sink("eval")
            .with_sink("exec")
            .with_sink("execSync")
            .with_sink("system")
            .with_sink("Popen")
            .with_sink("run")
            .with_sink("check_output")
            .with_sink("check_call")
            .with_sink("query")
            .with_sink("execute")
            .with_sanitizer("escape")
            .with_sanitizer("escapeShellArg")
            .with_sanitizer("quote");
        Self {
            id: RuleId::new("ai:llm-output-injection").expect("valid rule id"),
            analysis: TaintAnalysis::new(config),
        }
    }
}

impl Default for LlmOutputInjectionRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for LlmOutputInjectionRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn applies_to(&self, language: &LanguageIdentifier) -> bool {
        *language == LanguageIdentifier::typescript() || *language == LanguageIdentifier::python()
    }

    fn default_severity(&self) -> Severity {
        Severity::Blocker
    }

    fn issue_type(&self) -> IssueType {
        IssueType::Vulnerability
    }

    fn remediation_effort_minutes(&self) -> u32 {
        30
    }

    fn metadata(&self) -> RuleMetadata {
        RuleMetadata {
            description: "An LLM's reply is untrusted input, not trusted code: text read out of a chat-completion response reaches an execution or SQL sink without validation, letting a prompt-injected or hallucinated response run arbitrary commands.".into(),
            tags: vec!["security".into(), "ai-generated".into(), "llm".into(), "injection".into(), "owasp-a03".into()],
            cwe: Some(94),
            produces_hotspots: false,
        }
    }

    fn check(&self, _file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        self.analysis
            .find_flows(ast)
            .into_iter()
            .map(|flow| {
                Finding::new(
                    format!(
                        "LLM-generated output from `{}` reaches execution sink `{}` unsanitized: {}",
                        flow.source,
                        flow.sink,
                        flow.trace.join("; ")
                    ),
                    flow.sink_span,
                )
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use vord_rules_engine::AstParser;

    use super::*;

    fn check_ts(code: &str) -> Vec<Finding> {
        let file = SourceFile::new("t.ts", code, LanguageIdentifier::typescript()).unwrap();
        let ast = vord_parser_typescript::TypeScriptParser::new()
            .parse(&file)
            .unwrap();
        LlmOutputInjectionRule::new().check(&file, &ast)
    }

    fn check_py(code: &str) -> Vec<Finding> {
        let file = SourceFile::new("t.py", code, LanguageIdentifier::python()).unwrap();
        let ast = vord_parser_python::PythonParser::new()
            .parse(&file)
            .unwrap();
        LlmOutputInjectionRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_openai_chat_completion_content_flowing_into_eval_ts() {
        let findings = check_ts(
            "const completion = await client.chat.completions.create({ model: \"gpt-4\", messages });\nconst code = completion.choices[0].message.content;\neval(code);\n",
        );
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("choices[0].message.content"));
        assert!(findings[0].message.contains("eval"));
    }

    #[test]
    fn flags_anthropic_content_text_flowing_into_exec_sync_ts() {
        let findings = check_ts(
            "const response = await anthropic.messages.create({ model: \"claude\", messages });\nconst text = response.content[0].text;\nexecSync(text);\n",
        );
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("content[0].text"));
        assert!(findings[0].message.contains("execSync"));
    }

    #[test]
    fn flags_generic_message_content_flowing_into_query_ts() {
        let findings = check_ts(
            "const message = await agent.send(userInput);\nconst sql = message.content;\ndb.query(sql);\n",
        );
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("query"));
    }

    #[test]
    fn flags_openai_chat_completion_content_flowing_into_os_system_py() {
        let findings = check_py(
            "completion = client.chat.completions.create(model=\"gpt-4\", messages=messages)\ncode = completion.choices[0].message.content\nos.system(code)\n",
        );
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("choices[0].message.content"));
        assert!(findings[0].message.contains("system"));
    }

    #[test]
    fn flags_anthropic_content_text_flowing_into_subprocess_check_output_py() {
        let findings = check_py(
            "response = anthropic.messages.create(model=\"claude\", messages=messages)\ntext = response.content[0].text\nsubprocess.check_output(text, shell=True)\n",
        );
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("content[0].text"));
        assert!(findings[0].message.contains("check_output"));
    }

    #[test]
    fn clean_literal_flow_is_silent() {
        assert!(check_ts("const code = \"literal\";\neval(code);\n").is_empty());
    }

    #[test]
    fn sanitized_llm_output_is_silent() {
        let findings = check_ts(
            "const completion = await client.chat.completions.create({ model: \"gpt-4\", messages });\nconst code = completion.choices[0].message.content;\nconst safe = escapeShellArg(code);\nexecSync(safe);\n",
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn unrelated_content_property_is_not_a_source() {
        // `.content` on an object not named message/response/completion, and
        // not the indexed choices/content chains, should not be treated as
        // an LLM output source.
        assert!(
            check_ts("const page = fetchPage();\nconst body = page.content;\neval(body);\n")
                .is_empty()
        );
    }
}
