//! `vord mcp`: vord's CLI as Model Context Protocol tools over stdio.
//!
//! Every tool runs the real `vord` subcommand (this same executable) in the
//! server's working directory and returns its output — an agent asking for
//! a scan gets the scan, not a canned answer. A failed command comes back
//! with `isError: true`, so "could not check" never reads as a pass.

use serde_json::{Value, json};
use std::io::{self, BufRead};
use std::process::Command;

use crate::kickoff_engine::{ENGINES, engine_for_language, engine_languages_text, engine_names};

/// Output longer than this is cut, keeping the tail (where vord prints its
/// summary and gate verdict).
const MAX_OUTPUT_CHARS: usize = 20_000;

pub fn run_mcp_server() -> io::Result<()> {
    let stdin = io::stdin();
    let mut handle = stdin.lock();

    let mut line = String::new();
    while handle.read_line(&mut line)? > 0 {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            line.clear();
            continue;
        }

        if let Ok(req) = serde_json::from_str::<Value>(trimmed) {
            if let Some(resp) = handle_rpc_request(&req) {
                let resp_str = serde_json::to_string(&resp)
                    .expect("JSON serialization cannot fail for a valid Value");
                println!("{}", resp_str);
            }
        }

        line.clear();
    }

    Ok(())
}

fn tool_list() -> Value {
    json!([
        {
            "name": "vord_scan",
            "description": "Run vord's static analysis over a path and return the findings, health score and quality gate verdict.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "path": { "type": "string", "description": "Directory or file to scan (default: the workspace root)" }
                }
            }
        },
        {
            "name": "vord_holes",
            "description": "List the holes the blueprints leave open, as JSON: `vord:hole` regions still empty or holding a placeholder, and Wasp operations main.wasp imports but nobody implemented. Each hole is one task: fill it, writing only inside it; the rest of the file is generated and vord denies changes to it.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "path": { "type": "string", "description": "Directory to look in (default: the workspace root)" }
                }
            }
        },
        {
            "name": "vord_done",
            "description": "Ask the analyzer whether the task is finished: re-scan and compare against the baseline recorded with `vord agent baseline`. Returns {done, reason}.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "scope": { "type": "string", "description": "Path to re-scan (default: .)" },
                    "baseline": { "type": "string", "description": "Baseline file (default: .vord/agent-baseline.json)" },
                    "rule": { "type": "string", "description": "A rule the task must eliminate from the scope" }
                }
            }
        },
        {
            "name": "vord_kickoff",
            "description": format!("Scaffold a project deterministically instead of writing boilerplate: either a built-in vord template, or a scaffolding engine ({}) from its blueprint. The result is policy-gated, with generated files recorded so later edits go through the blueprint.", engine_names().join(", ")),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "template": { "type": "string", "description": "Built-in template (single-language skeleton, NOT an engine): react-bulletproof, rust-clean, python-clean, typescript-clean, fullstack-hexagonal. Cannot be combined with `engine`." },
                    "engine": { "type": "string", "enum": engine_names(), "description": format!("Scaffolding engine, chosen by the language of the backend: {}. Requires name. Do not delete or hand-rewrite generated output: change the blueprint and regenerate. copier takes a template path or git URL as blueprint; openapi takes a spec as blueprint and needs `generator`.", engine_languages_text()) },
                    "frontend": { "type": "string", "enum": ["wasp"], "description": "With a ferrum, kthulu or openapi (spec-first; needs `generator` and `blueprint`) `engine` as the backend, also generate a Wasp frontend joined by a shared OpenAPI contract (contract/openapi.yaml)" },
                    "language": { "type": "string", "description": "Backend language the user asked for (rust, go, typescript); checked against `engine` so a mismatch is rejected" },
                    "generator": { "type": "string", "description": "With engine openapi: the OpenAPI Generator name, e.g. typescript-fetch" },
                    "data": { "type": "object", "additionalProperties": { "type": ["string", "number", "boolean"] }, "description": "With engine copier: template answers as {question: value}, passed as `copier copy --data question=value`" },
                    "entities": { "type": "object", "additionalProperties": { "type": "object", "additionalProperties": { "type": "string", "enum": ["string", "int", "float", "bool", "uuid", "datetime"] } }, "description": "The app to create, as entities with typed fields, e.g. {\"todo\": {\"title\": \"string\", \"done\": \"bool\"}}. With engine ferrum, vord derives the graph (CRUD use cases) and, with `frontend`, the OpenAPI contract: do not write either by hand. Cannot be combined with `blueprint`." },
                    "vcs_ref": { "type": "string", "description": "With engine copier: template tag, branch or commit (`--vcs-ref`); copier defaults to the latest tag" },
                    "install": { "type": "boolean", "description": "Install the engine if it is not on PATH. Only engines with a pinned installer (see --list-engines); Wasp must be installed by the user and this flag does nothing for it" },
                    "plan": { "type": "boolean", "description": "Only print the commands that would run" },
                    "name": { "type": "string", "description": "Project name passed to the engine" },
                    "blueprint": { "type": "string", "description": "Engine blueprint: kthulu-plan.yaml or a ferrum graph YAML" },
                    "path": { "type": "string", "description": "Destination (with an engine: the PARENT directory; the project is created in <path>/<name>, so do not repeat the name in path)" }
                }
            }
        },
        {
            "name": "vord_swarm_roles",
            "description": "List the swarm roles declared in vord.toml with their worktree, model and policy scope.",
            "inputSchema": { "type": "object", "properties": {} }
        },
        {
            "name": "vord_swarm_handoff",
            "description": "Send a swarm handoff from one role to another (written to the sender's outbox, then delivered).",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "from": { "type": "string" },
                    "to": { "type": "string" },
                    "summary": { "type": "string" }
                },
                "required": ["from", "to", "summary"]
            }
        }
    ])
}

fn string_arg<'a>(args: &'a Value, key: &str) -> Option<&'a str> {
    args.get(key).and_then(Value::as_str).filter(|s| !s.is_empty())
}

/// The `vord` invocations a tool call maps to, or why it cannot run.
fn tool_commands(name: &str, args: &Value) -> Result<Vec<Vec<String>>, String> {
    let owned = |parts: &[&str]| parts.iter().map(|s| s.to_string()).collect::<Vec<_>>();
    match name {
        "vord_scan" => Ok(vec![owned(&["scan", string_arg(args, "path").unwrap_or(".")])]),
        "vord_holes" => Ok(vec![owned(&["holes", string_arg(args, "path").unwrap_or("."), "--json"])]),
        "vord_done" => {
            let mut argv = owned(&["agent", "done", "--json", "--scope", string_arg(args, "scope").unwrap_or(".")]);
            if let Some(baseline) = string_arg(args, "baseline") {
                argv.extend(owned(&["--baseline", baseline]));
            }
            if let Some(rule) = string_arg(args, "rule") {
                argv.extend(owned(&["--rule", rule]));
            }
            Ok(vec![argv])
        }
        "vord_kickoff" => {
            let mut argv = owned(&["kickoff"]);
            match (string_arg(args, "engine"), string_arg(args, "template")) {
                (Some(engine), template) => {
                    if template.is_some() {
                        return Err(format!(
                            "vord_kickoff: `template` and `engine` are mutually exclusive; templates are not engines (use one of: {})",
                            engine_languages_text()
                        ));
                    }
                    let languages = engine_languages_text();
                    let spec = ENGINES.iter().find(|spec| spec.name == engine);
                    // Engines picked by backend language only; copier and openapi are not.
                    if let (Some(language), true) = (string_arg(args, "language"), spec.is_some_and(|s| !s.languages.is_empty())) {
                        let expected = engine_for_language(language).map(|spec| spec.name).ok_or_else(|| {
                            format!("vord_kickoff: no engine for language {language:?} ({languages})")
                        })?;
                        if expected != engine {
                            return Err(format!(
                                "vord_kickoff: engine {engine:?} does not generate {language}; use engine {expected:?} ({languages})"
                            ));
                        }
                    }
                    if let Some(spec) = spec {
                        for required in spec.required_args {
                            if string_arg(args, required).is_none() {
                                return Err(format!("vord_kickoff with an engine needs `{required}`"));
                            }
                        }
                    }
                    let name = string_arg(args, "name")
                        .ok_or("vord_kickoff with an engine needs `name`")?;
                    argv.extend(owned(&["--engine", engine, "--name", name]));
                    if let Some(generator) = string_arg(args, "generator") {
                        argv.extend(owned(&["--generator", generator]));
                    }
                    for flag in ["install", "plan"] {
                        if args.get(flag).and_then(Value::as_bool) == Some(true) {
                            argv.push(format!("--{flag}"));
                        }
                    }
                    if let Some(data) = args.get("data") {
                        let map = data.as_object().ok_or("vord_kickoff `data` must be an object of answers")?;
                        for (key, value) in map {
                            let text = match value {
                                Value::String(s) => s.clone(),
                                Value::Number(n) => n.to_string(),
                                Value::Bool(b) => b.to_string(),
                                _ => return Err(format!("vord_kickoff `data.{key}` must be a string, number or boolean")),
                            };
                            argv.extend(["--data".to_string(), format!("{key}={text}")]);
                        }
                    }
                    if let Some(entities) = args.get("entities") {
                        let map = entities.as_object().ok_or(
                            "vord_kickoff `entities` must be an object of {entity: {field: type}}",
                        )?;
                        for (entity, fields) in map {
                            let fields = fields.as_object().ok_or_else(|| format!("vord_kickoff `entities.{entity}` must be an object of {{field: type}}"))?;
                            let mut pairs = Vec::new();
                            for (field, ty) in fields {
                                let ty = ty.as_str().ok_or_else(|| format!("vord_kickoff `entities.{entity}.{field}` must be a type name"))?;
                                pairs.push(format!("{field}={ty}"));
                            }
                            argv.extend([
                                "--entity".to_string(),
                                format!("{entity}:{}", pairs.join(",")),
                            ]);
                        }
                    }
                    if let Some(vcs_ref) = string_arg(args, "vcs_ref") {
                        argv.extend(owned(&["--vcs-ref", vcs_ref]));
                    }
                    if let Some(frontend) = string_arg(args, "frontend") {
                        argv.extend(owned(&["--frontend", frontend]));
                    }
                    if let Some(blueprint) = string_arg(args, "blueprint") {
                        argv.extend(owned(&["--blueprint", blueprint]));
                    }
                }
                (None, Some(_)) if string_arg(args, "language").is_some() => {
                    return Err("vord_kickoff: `language` selects an engine; pass `engine` or drop `language`".into())
                }
                (None, Some(template)) => argv.push(template.to_string()),
                (None, None) => return Err("vord_kickoff needs `template` or `engine`".into()),
            }
            argv.extend(owned(&["--path", string_arg(args, "path").unwrap_or(".")]));
            Ok(vec![argv])
        }
        "vord_swarm_roles" => Ok(vec![owned(&["swarm", "roles"])]),
        "vord_swarm_handoff" => {
            let field = |key: &str| string_arg(args, key).ok_or(format!("vord_swarm_handoff needs `{key}`"));
            Ok(vec![
                owned(&["swarm", "handoff-send", "--from", field("from")?, "--to", field("to")?, "--summary", field("summary")?]),
                owned(&["swarm", "handoff-deliver"]),
            ])
        }
        other => Err(format!("unknown tool {other:?}")),
    }
}

/// Exit codes that are verdicts, not failures: `vord agent done` exits 3
/// for "not done yet", and a scan's gate does the same.
fn is_verdict_exit(code: Option<i32>) -> bool {
    matches!(code, Some(0) | Some(3))
}

fn tail(text: &str) -> String {
    let count = text.chars().count();
    if count <= MAX_OUTPUT_CHARS {
        return text.to_string();
    }
    let kept: String = text.chars().skip(count - MAX_OUTPUT_CHARS).collect();
    format!("[… {} characters cut …]\n{kept}", count - MAX_OUTPUT_CHARS)
}

/// Runs a tool's commands in order and returns `(text, is_error)`.
fn run_tool(name: &str, args: &Value) -> (String, bool) {
    let commands = match tool_commands(name, args) {
        Ok(commands) => commands,
        Err(message) => return (message, true),
    };
    let exe = match std::env::current_exe() {
        Ok(exe) => exe,
        Err(e) => return (format!("cannot locate the vord executable: {e}"), true),
    };
    let mut transcript = String::new();
    for argv in commands {
        let output = match Command::new(&exe).args(&argv).output() {
            Ok(output) => output,
            Err(e) => return (format!("could not run vord {}: {e}", argv.join(" ")), true),
        };
        transcript.push_str(&String::from_utf8_lossy(&output.stdout));
        transcript.push_str(&String::from_utf8_lossy(&output.stderr));
        if !is_verdict_exit(output.status.code()) {
            transcript.push_str(&format!("\nvord {} failed ({})", argv.join(" "), output.status));
            return (tail(&transcript), true);
        }
    }
    (tail(&transcript), false)
}

fn handle_rpc_request(req: &Value) -> Option<Value> {
    let id = req.get("id")?;
    let method = req.get("method")?.as_str()?;

    match method {
        "initialize" => Some(json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": {
                    "tools": {}
                },
                "serverInfo": {
                    "name": "vord-mcp",
                    "version": env!("CARGO_PKG_VERSION")
                }
            }
        })),
        "tools/list" => Some(json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": { "tools": tool_list() }
        })),
        "tools/call" => {
            let params = req.get("params")?;
            let name = params.get("name")?.as_str()?;
            let args = params.get("arguments").cloned().unwrap_or(json!({}));
            let (text, is_error) = run_tool(name, &args);
            Some(json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": {
                    "content": [{ "type": "text", "text": text }],
                    "isError": is_error
                }
            }))
        }
        _ => Some(json!({
            "jsonrpc": "2.0",
            "id": id,
            "error": {
                "code": -32601,
                "message": "Method not found"
            }
        })),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handles_mcp_initialize_rpc_request() {
        let req = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize"
        });

        let resp = handle_rpc_request(&req).unwrap();
        assert_eq!(resp["result"]["serverInfo"]["name"], "vord-mcp");
    }

    #[test]
    fn handles_mcp_tools_list_rpc_request() {
        let req = json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/list"
        });

        let resp = handle_rpc_request(&req).unwrap();
        let tools = resp["result"]["tools"].as_array().unwrap();
        assert!(tools.iter().any(|t| t["name"] == "vord_scan"));
        assert!(tools.iter().any(|t| t["name"] == "vord_kickoff"));
        assert!(tools.iter().any(|t| t["name"] == "vord_done"));
        assert!(tools.iter().any(|t| t["name"] == "vord_holes"));
    }

    #[test]
    fn every_listed_tool_maps_to_a_real_vord_command() {
        let args = json!({ "engine": "kthulu", "name": "shop", "from": "a", "to": "b", "summary": "s" });
        for tool in tool_list().as_array().unwrap() {
            let name = tool["name"].as_str().unwrap();
            assert!(tool_commands(name, &args).is_ok(), "{name} has no command");
        }
    }

    #[test]
    fn kickoff_maps_engines_and_templates() {
        assert_eq!(
            tool_commands("vord_kickoff", &json!({ "engine": "ferrum", "name": "shop", "blueprint": "g.yaml" })).unwrap(),
            [["kickoff", "--engine", "ferrum", "--name", "shop", "--blueprint", "g.yaml", "--path", "."]]
        );
        assert_eq!(
            tool_commands("vord_kickoff", &json!({ "template": "rust-clean", "path": "svc" })).unwrap(),
            [["kickoff", "rust-clean", "--path", "svc"]]
        );
        assert!(tool_commands("vord_kickoff", &json!({ "engine": "wasp" })).is_err(), "engine needs a name");
    }

    #[test]
    fn kickoff_passes_copier_answers_as_repeated_data_flags() {
        let argv = tool_commands(
            "vord_kickoff",
            &json!({ "engine": "copier", "name": "api", "blueprint": "gh:o/t", "vcs_ref": "0.9.0", "data": { "project_name": "My API", "n": 3, "on": true } }),
        )
        .unwrap();
        let argv = &argv[0];
        assert!(argv.windows(2).any(|w| w == ["--data", "project_name=My API"]));
        assert!(argv.windows(2).any(|w| w == ["--data", "n=3"]));
        assert!(argv.windows(2).any(|w| w == ["--data", "on=true"]));
        assert!(argv.windows(2).any(|w| w == ["--vcs-ref", "0.9.0"]));
        let bad = json!({ "engine": "copier", "name": "api", "blueprint": "x", "data": { "k": ["a"] } });
        assert!(tool_commands("vord_kickoff", &bad).is_err());
        let bad = json!({ "engine": "copier", "name": "api", "blueprint": "x", "data": "k=v" });
        assert!(tool_commands("vord_kickoff", &bad).is_err());
    }


    #[test]
    fn kickoff_turns_entities_into_entity_flags() {
        let argv = tool_commands(
            "vord_kickoff",
            &json!({ "engine": "ferrum", "name": "todo", "entities": { "todo": { "title": "string", "done": "bool" } } }),
        )
        .unwrap();
        assert!(
            argv[0]
                .windows(2)
                .any(|w| w == ["--entity", "todo:done=bool,title=string"]),
            "{:?}",
            argv[0]
        );
        let bad = json!({ "engine": "ferrum", "name": "todo", "entities": { "todo": ["title"] } });
        assert!(tool_commands("vord_kickoff", &bad).is_err());
    }

    #[test]
    fn kickoff_rejects_incoherent_engine_choices() {
        let err = tool_commands("vord_kickoff", &json!({ "engine": "kthulu", "template": "typescript-clean", "name": "x" })).unwrap_err();
        assert!(err.contains("mutually exclusive"), "{err}");
        let err = tool_commands("vord_kickoff", &json!({ "engine": "kthulu", "language": "rust", "name": "x" })).unwrap_err();
        assert!(err.contains("ferrum"), "{err}");
        assert!(tool_commands("vord_kickoff", &json!({ "engine": "ferrum", "language": "Rust", "name": "x" })).is_ok());
        assert!(tool_commands("vord_kickoff", &json!({ "engine": "ferrum", "language": "cobol", "name": "x" })).is_err());
    }

    #[test]
    fn unknown_tools_and_missing_arguments_are_errors_not_canned_success() {
        let (text, is_error) = run_tool("vord_nope", &json!({}));
        assert!(is_error, "{text}");
        let (_, is_error) = run_tool("vord_swarm_handoff", &json!({ "from": "a" }));
        assert!(is_error);
    }

    #[test]
    fn long_output_keeps_the_tail() {
        let long = format!("{}SUMMARY", "x".repeat(MAX_OUTPUT_CHARS + 10));
        let cut = tail(&long);
        assert!(cut.ends_with("SUMMARY"));
        assert!(cut.starts_with("[… 10 characters cut …]") || cut.contains("characters cut"));
    }
}
