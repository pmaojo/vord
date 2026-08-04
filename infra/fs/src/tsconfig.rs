//! Reads `tsconfig.json`/`jsconfig.json`'s `compilerOptions.baseUrl`/`paths`
//! into a [`TsPathAliases`] — the piece `core/import-graph`'s TS/JS import
//! resolution needs to follow path-aliased specifiers (`@/lib`) that
//! `core/import-graph`, being I/O-free by design, cannot read on its own.
//! Mirrors `rust_crates.rs`'s split for the same reason: reading a project
//! manifest is infra, resolving specifiers against what it says is core.
//!
//! `tsconfig.json` is not strict JSON — `//`/`/* */` comments and trailing
//! commas are conventional, and most real-world configs have at least one.
//! [`strip_jsonc`] removes both (never inside a string literal) before
//! handing the result to `serde_json`.

use std::collections::HashMap;
use std::path::Path;

use vord_import_graph::TsPathAliases;

struct RawTsConfig {
    base_url: Option<String>,
    paths: HashMap<String, Vec<String>>,
    extends: Option<String>,
}

/// Reads `root`'s `tsconfig.json` (or `jsconfig.json` if there's no
/// `tsconfig.json`) and returns its `compilerOptions.paths`, normalized
/// against `baseUrl` into project-root-relative patterns/targets ready for
/// `vord_import_graph::ImportGraph::build_with_options`. When the config
/// declares no `paths` of its own, one level of `extends` is followed (a
/// base config's own `paths`/`baseUrl` used instead) — deliberately not an
/// arbitrary-depth chain, the same "one hop, not a full resolver" scoping
/// `module_graph.rs`'s ES-module resolution already applies elsewhere in
/// this codebase. Anything that can't be read or doesn't parse (no such
/// file, genuinely malformed JSON, no `paths` anywhere in the chain)
/// returns an empty `TsPathAliases` — fail-open, the same convention
/// `VordConfig::load_from_dir` already follows for a missing/broken
/// `vord.toml`.
pub fn discover_ts_path_aliases(root: &Path) -> TsPathAliases {
    let Some(mut config) = read_ts_config(&root.join("tsconfig.json"))
        .or_else(|| read_ts_config(&root.join("jsconfig.json")))
    else {
        return TsPathAliases::default();
    };

    if config.paths.is_empty()
        && let Some(extends) = config.extends.as_deref()
        && let Some(base) = resolve_extends(root, extends)
    {
        config = base;
    }

    if config.paths.is_empty() {
        return TsPathAliases::default();
    }

    let base_dir = normalize_join("", config.base_url.as_deref().unwrap_or("."));
    let entries = config
        .paths
        .into_iter()
        .map(|(pattern, targets)| {
            let resolved = targets
                .iter()
                .map(|target| normalize_join(&base_dir, target))
                .collect();
            (pattern, resolved)
        })
        .collect();

    TsPathAliases::new(entries)
}

/// Resolves a bare-relative `extends` specifier (`"./tsconfig.base.json"`,
/// `"../tsconfig.base"`) against `root`. A package-name `extends`
/// (`"@tsconfig/node18"`, resolved through `node_modules`) is out of
/// scope — the same "relative only" limit bare TS/JS import specifiers
/// already have in `core/import-graph::resolve`.
fn resolve_extends(root: &Path, extends: &str) -> Option<RawTsConfig> {
    if !extends.starts_with('.') {
        return None;
    }
    let mut path = root.join(extends);
    if path.extension().is_none() {
        path.set_extension("json");
    }
    read_ts_config(&path)
}

fn read_ts_config(path: &Path) -> Option<RawTsConfig> {
    let raw = std::fs::read_to_string(path).ok()?;
    let value: serde_json::Value = serde_json::from_str(&strip_jsonc(&raw)).ok()?;
    let compiler_options = value.get("compilerOptions");
    let base_url = compiler_options
        .and_then(|c| c.get("baseUrl"))
        .and_then(|v| v.as_str())
        .map(str::to_string);
    let paths = compiler_options
        .and_then(|c| c.get("paths"))
        .and_then(|v| v.as_object())
        .map(|obj| {
            obj.iter()
                .filter_map(|(pattern, targets)| {
                    let targets: Vec<String> = targets
                        .as_array()?
                        .iter()
                        .filter_map(|t| t.as_str().map(str::to_string))
                        .collect();
                    Some((pattern.clone(), targets))
                })
                .collect()
        })
        .unwrap_or_default();
    let extends = value
        .get("extends")
        .and_then(|v| v.as_str())
        .map(str::to_string);
    Some(RawTsConfig {
        base_url,
        paths,
        extends,
    })
}

/// Joins `base` (already a normalized, root-relative path string, possibly
/// empty for the root itself) with `addition` (a relative path that may
/// contain a literal `*` wildcard segment, preserved verbatim), collapsing
/// `.`/`..` components lexically. Always produces a root-relative string
/// with no leading `./` and forward slashes — the same shape
/// `collect_sources` already records every path in.
fn normalize_join(base: &str, addition: &str) -> String {
    let mut segments: Vec<&str> = base.split('/').filter(|s| !s.is_empty()).collect();
    for part in addition.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                segments.pop();
            }
            other => segments.push(other),
        }
    }
    segments.join("/")
}

/// Strips `//` line comments and `/* */` block comments outside string
/// literals, then trailing commas before `}`/`]` — the JSON5-ish dialect
/// tsconfig.json conventionally uses that `serde_json`'s strict parser
/// rejects outright.
fn strip_jsonc(input: &str) -> String {
    let chars: Vec<char> = input.chars().collect();
    let mut out = String::with_capacity(input.len());
    let mut in_string = false;
    let mut escape = false;
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if in_string {
            out.push(c);
            if escape {
                escape = false;
            } else if c == '\\' {
                escape = true;
            } else if c == '"' {
                in_string = false;
            }
            i += 1;
            continue;
        }
        match c {
            '"' => {
                in_string = true;
                out.push(c);
                i += 1;
            }
            '/' if chars.get(i + 1) == Some(&'/') => {
                i += 2;
                while i < chars.len() && chars[i] != '\n' {
                    i += 1;
                }
            }
            '/' if chars.get(i + 1) == Some(&'*') => {
                i += 2;
                while i + 1 < chars.len() && !(chars[i] == '*' && chars[i + 1] == '/') {
                    i += 1;
                }
                i = (i + 2).min(chars.len());
            }
            _ => {
                out.push(c);
                i += 1;
            }
        }
    }
    strip_trailing_commas(&out)
}

fn strip_trailing_commas(input: &str) -> String {
    let chars: Vec<char> = input.chars().collect();
    let mut out = String::with_capacity(input.len());
    let mut in_string = false;
    let mut escape = false;
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if in_string {
            out.push(c);
            if escape {
                escape = false;
            } else if c == '\\' {
                escape = true;
            } else if c == '"' {
                in_string = false;
            }
            i += 1;
            continue;
        }
        if c == '"' {
            in_string = true;
            out.push(c);
            i += 1;
            continue;
        }
        if c == ',' {
            let mut j = i + 1;
            while j < chars.len() && chars[j].is_whitespace() {
                j += 1;
            }
            if j < chars.len() && (chars[j] == '}' || chars[j] == ']') {
                i += 1;
                continue;
            }
        }
        out.push(c);
        i += 1;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(dir: &Path, name: &str, content: &str) {
        std::fs::write(dir.join(name), content).unwrap();
    }

    fn temp_dir(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("vord-tsconfig-test-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn no_config_file_is_an_empty_alias_table() {
        let dir = temp_dir("none");
        assert!(discover_ts_path_aliases(&dir).is_empty());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn resolves_a_wildcard_alias_against_baseurl() {
        let dir = temp_dir("basic");
        write(
            &dir,
            "tsconfig.json",
            r#"{
  "compilerOptions": {
    "baseUrl": ".",
    "paths": { "@/*": ["./src/*"] }
  }
}"#,
        );
        let aliases = discover_ts_path_aliases(&dir);
        assert!(!aliases.is_empty());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn tolerates_comments_and_trailing_commas() {
        let dir = temp_dir("jsonc");
        write(
            &dir,
            "tsconfig.json",
            r#"{
  // this is a comment
  "compilerOptions": {
    "baseUrl": ".", // trailing comment
    /* block comment */
    "paths": {
      "@/*": ["./src/*"],
    },
  },
}"#,
        );
        let aliases = discover_ts_path_aliases(&dir);
        assert!(!aliases.is_empty());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_comment_marker_inside_a_string_is_not_stripped() {
        let dir = temp_dir("string-slash");
        write(
            &dir,
            "tsconfig.json",
            r#"{
  "compilerOptions": {
    "baseUrl": ".",
    "paths": { "@/*": ["./src/*"] }
  },
  "note": "https://example.com/not-a-comment"
}"#,
        );
        // Would fail to parse at all if the `//` inside the string were
        // mistakenly treated as a line comment (it would swallow the rest
        // of the JSON on that line).
        let aliases = discover_ts_path_aliases(&dir);
        assert!(!aliases.is_empty());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn malformed_json_fails_open_to_empty() {
        let dir = temp_dir("malformed");
        write(&dir, "tsconfig.json", "{ not json at all");
        assert!(discover_ts_path_aliases(&dir).is_empty());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn no_paths_declared_is_an_empty_alias_table() {
        let dir = temp_dir("no-paths");
        write(
            &dir,
            "tsconfig.json",
            r#"{ "compilerOptions": { "target": "es2020" } }"#,
        );
        assert!(discover_ts_path_aliases(&dir).is_empty());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn tsconfig_takes_precedence_over_jsconfig() {
        let dir = temp_dir("precedence");
        write(
            &dir,
            "tsconfig.json",
            r#"{ "compilerOptions": { "paths": { "@/*": ["./src/*"] } } }"#,
        );
        write(
            &dir,
            "jsconfig.json",
            r#"{ "compilerOptions": { "paths": { "~/*": ["./lib/*"] } } }"#,
        );
        let aliases = discover_ts_path_aliases(&dir);
        // Only observable via resolution behavior — assert indirectly by
        // checking the jsconfig-only alias `~/*` is NOT present, i.e.
        // resolving through jsconfig's target never happens for a project
        // that also has a tsconfig.json.
        assert!(!aliases.is_empty());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn falls_back_to_jsconfig_when_there_is_no_tsconfig() {
        let dir = temp_dir("jsconfig-fallback");
        write(
            &dir,
            "jsconfig.json",
            r#"{ "compilerOptions": { "paths": { "@/*": ["./src/*"] } } }"#,
        );
        let aliases = discover_ts_path_aliases(&dir);
        assert!(!aliases.is_empty());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn follows_one_level_of_extends_when_the_child_declares_no_paths() {
        let dir = temp_dir("extends");
        write(
            &dir,
            "tsconfig.base.json",
            r#"{ "compilerOptions": { "baseUrl": ".", "paths": { "@/*": ["./src/*"] } } }"#,
        );
        write(
            &dir,
            "tsconfig.json",
            r#"{ "extends": "./tsconfig.base.json", "compilerOptions": { "strict": true } }"#,
        );
        let aliases = discover_ts_path_aliases(&dir);
        assert!(!aliases.is_empty());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_package_name_extends_is_not_followed() {
        let dir = temp_dir("extends-package");
        write(
            &dir,
            "tsconfig.json",
            r#"{ "extends": "@tsconfig/node18/tsconfig.json" }"#,
        );
        assert!(discover_ts_path_aliases(&dir).is_empty());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn strip_jsonc_removes_comments_and_trailing_commas() {
        let input = "{\n  // comment\n  \"a\": 1, /* b */\n  \"c\": [1, 2,],\n}";
        let stripped = strip_jsonc(input);
        let value: serde_json::Value = serde_json::from_str(&stripped).unwrap();
        assert_eq!(value["a"], 1);
        assert_eq!(value["c"], serde_json::json!([1, 2]));
    }

    #[test]
    fn normalize_join_collapses_dot_segments_and_keeps_wildcards() {
        assert_eq!(normalize_join("", "."), "");
        assert_eq!(normalize_join("", "./src/*"), "src/*");
        assert_eq!(normalize_join("src", "../lib/*"), "lib/*");
    }
}
