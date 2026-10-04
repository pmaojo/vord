//! Hole-driven development: `vord holes` and `vord agent fill`.
//!
//! A scaffolding engine writes everything a blueprint determines and leaves
//! **holes** for what it cannot: business rules, provider calls, the body of
//! an operation. Finding those holes is deterministic, so no model does it:
//!
//! - a `vord:hole <name>` … `vord:end-hole` region whose body is still empty
//!   or a placeholder (`vord_agent_policy::generated`);
//! - a Wasp operation, page or job that `main.wasp` imports from `src/` but
//!   that is not implemented yet — Wasp needs no markers, because its
//!   blueprint already says which functions are hand-written.
//!
//! `vord agent fill` then gives the model one hole at a time, a task that
//! names exactly what to write and where, and the write gate keeps it inside
//! the hole. Whether a hole got filled is checked again deterministically
//! after the run; the model's word is not taken for it.

use std::path::{Path, PathBuf};

use regex::Regex;
use serde::Serialize;
use vord_agent::RunOutcome;
use vord_agent_policy::generated::{self, HOLE_OPEN};

use crate::agent::{self, AgentArgs};

/// Larger files are not read when looking for holes; generators do not emit
/// megabyte sources, and this keeps a scan over vendored blobs cheap.
const MAX_FILE_BYTES: u64 = 1024 * 1024;

/// Where a pending hole comes from.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum HoleKind {
    /// A `vord:hole` region in a source file.
    Marker,
    /// A function `main.wasp` imports from `src/` that does not exist yet.
    WaspImport,
}

/// One piece of hand-written work the blueprint left open.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct PendingHole {
    pub kind: HoleKind,
    /// Repository-relative file the code goes in.
    pub file: String,
    /// The hole's name, or for Wasp the declaration (`query getTasks`).
    pub name: String,
    /// First and last line of the hole (Wasp: the declaration's line in the
    /// `.wasp` file, since the code does not exist yet).
    pub line: u32,
    pub end_line: u32,
    /// For Wasp: the `.wasp` file that declares it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub declared_in: Option<String>,
    /// For Wasp: the export the declaration imports.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub export: Option<String>,
    /// Why it counts as pending.
    pub reason: String,
}

fn relative(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

/// Every pending hole under `root/scope`, in path order. `.wasp/` (Wasp's
/// generated output), `node_modules/` and anything git ignores are skipped.
pub fn scan(root: &Path, scope: &str) -> Vec<PendingHole> {
    let start = root.join(scope);
    let mut files: Vec<PathBuf> = ignore::WalkBuilder::new(&start)
        .hidden(false)
        .filter_entry(|entry| {
            !matches!(
                entry.file_name().to_str(),
                Some(".git" | ".wasp" | "node_modules" | "target")
            )
        })
        .build()
        .flatten()
        .filter(|entry| entry.file_type().is_some_and(|t| t.is_file()))
        .map(|entry| entry.into_path())
        .collect();
    files.sort();

    let mut out = Vec::new();
    for path in files {
        if path.metadata().map(|m| m.len() > MAX_FILE_BYTES).unwrap_or(true) {
            continue;
        }
        let Ok(content) = std::fs::read_to_string(&path) else {
            continue;
        };
        if path.extension().is_some_and(|e| e == "wasp") {
            out.extend(wasp_holes(root, &path, &content));
        } else if content.contains(HOLE_OPEN) {
            out.extend(marker_holes(&relative(root, &path), &content));
        }
    }
    out
}

fn marker_holes(file: &str, content: &str) -> Vec<PendingHole> {
    generated::holes(content)
        .into_iter()
        .filter(|hole| hole.is_pending())
        .map(|hole| PendingHole {
            kind: HoleKind::Marker,
            file: file.to_string(),
            name: hole.name,
            line: hole.open_line,
            end_line: hole.close_line,
            declared_in: None,
            export: None,
            reason: "empty or placeholder".to_string(),
        })
        .collect()
}

/// The Wasp declarations (`query`, `action`, `page`, …) whose `src/` imports
/// do not resolve to an implemented export.
fn wasp_holes(root: &Path, wasp_file: &Path, content: &str) -> Vec<PendingHole> {
    let project = wasp_file.parent().unwrap_or(root);
    let declaration = Regex::new(r"(?m)^(\w+)\s+(\w+)\s*\{").expect("valid regex");
    let import = Regex::new(
        r#"import\s*(?:\{\s*(\w+)(?:\s+as\s+\w+)?\s*\}|(\w+))\s*from\s*"@(src|server|client)/([^"]+)""#,
    )
    .expect("valid regex");
    let declarations: Vec<(usize, String)> = declaration
        .captures_iter(content)
        .map(|c| {
            let whole = c.get(0).expect("group 0");
            (whole.start(), format!("{} {}", &c[1], &c[2]))
        })
        .collect();

    let mut out = Vec::new();
    for capture in import.captures_iter(content) {
        let at = capture.get(0).expect("group 0").start();
        let (export, is_default) = match (capture.get(1), capture.get(2)) {
            (Some(named), _) => (named.as_str().to_string(), false),
            (None, Some(default)) => (default.as_str().to_string(), true),
            (None, None) => continue,
        };
        // Wasp < 0.12 imported from `@server/…` and `@client/…`, which
        // live under `src/server` and `src/client`.
        let module = match &capture[3] {
            "src" => capture[4].to_string(),
            alias => format!("{alias}/{}", &capture[4]),
        };
        let owner = declarations
            .iter()
            .rev()
            .find(|(start, _)| *start < at)
            .map(|(_, name)| name.clone())
            .unwrap_or_else(|| export.clone());
        let line = u32::try_from(content[..at].lines().count().max(1)).unwrap_or(u32::MAX);
        let (file, reason) = match resolve_module(&project.join("src"), &module) {
            None => (
                relative(root, &project.join("src").join(format!("{module}.ts"))),
                "file does not exist".to_string(),
            ),
            Some(path) => {
                let source = std::fs::read_to_string(&path).unwrap_or_default();
                if exports(&source, &export, is_default) {
                    continue;
                }
                (relative(root, &path), format!("no export `{export}`"))
            }
        };
        out.push(PendingHole {
            kind: HoleKind::WaspImport,
            file,
            name: owner,
            line,
            end_line: line,
            declared_in: Some(relative(root, wasp_file)),
            export: Some(export),
            reason,
        });
    }
    out
}

/// `src/<module>` as Wasp resolves it: the path as written, or with a JS/TS
/// extension, or its `index` file.
fn resolve_module(src: &Path, module: &str) -> Option<PathBuf> {
    let base = src.join(module);
    if base.is_file() {
        return Some(base);
    }
    const EXTENSIONS: [&str; 4] = ["ts", "tsx", "js", "jsx"];
    EXTENSIONS
        .iter()
        .map(|ext| base.with_extension(ext))
        .chain(EXTENSIONS.iter().map(|ext| base.join(format!("index.{ext}"))))
        .find(|candidate| candidate.is_file())
}

fn exports(source: &str, name: &str, is_default: bool) -> bool {
    let pattern = if is_default {
        r"export\s+default\b".to_string()
    } else {
        let name = regex::escape(name);
        format!(
            r"export\s+(?:async\s+)?(?:const|let|var|function\*?|class)\s+{name}\b|export\s*\{{[^}}]*\b{name}\b"
        )
    };
    Regex::new(&pattern).expect("valid regex").is_match(source)
}

/// Human-readable list, one line per hole.
pub fn render_text(holes: &[PendingHole]) -> String {
    if holes.is_empty() {
        return "No pending holes: everything the blueprints leave open is written.\n".into();
    }
    let mut out = String::new();
    for hole in holes {
        match hole.kind {
            HoleKind::Marker => out.push_str(&format!(
                "{}:{}-{}  hole {}\n",
                hole.file,
                hole.line,
                if hole.end_line > hole.line { hole.end_line } else { hole.line },
                display_name(&hole.name)
            )),
            HoleKind::WaspImport => out.push_str(&format!(
                "{}  {} (declared in {}:{}): {}\n",
                hole.file,
                hole.name,
                hole.declared_in.as_deref().unwrap_or("main.wasp"),
                hole.line,
                hole.reason
            )),
        }
    }
    out.push_str(&format!("{} pending hole(s)\n", holes.len()));
    out
}

fn display_name(name: &str) -> &str {
    if name.is_empty() {
        "(unnamed)"
    } else {
        name
    }
}

/// The task one fill run is given. It names the file, the hole and the
/// boundary, so the model spends its turns on the residue, not on finding it.
pub fn task_for(hole: &PendingHole) -> String {
    match hole.kind {
        HoleKind::Marker => format!(
            "Fill the hole `{name}` in `{file}`: the lines between the `vord:hole {name}` marker \
             (line {open}) and the next `vord:end-hole` (line {close}). Replace the placeholder \
             with the hand-written code this hole is for; read the surrounding code and any tests \
             to work out what it must do. Write only inside this hole and keep both marker lines: \
             the rest of the file is generated and vord denies any change to it. If the hole \
             cannot be filled without changing generated code, stop and say which blueprint \
             change is needed instead.",
            name = display_name(&hole.name),
            file = hole.file,
            open = hole.line,
            close = hole.end_line,
        ),
        HoleKind::WaspImport => format!(
            "Implement `{export}` in `{file}` ({reason}). It is the {name} declared in \
             `{wasp}` at line {line}; read that declaration (its entities, auth, route) and \
             implement exactly what it imports, with the signature Wasp expects for it. Create \
             the file if needed. Do not edit `{wasp}` or anything under `.wasp/`: they are the \
             blueprint and its generated output.",
            export = hole.export.as_deref().unwrap_or("the import"),
            file = hole.file,
            reason = hole.reason,
            name = hole.name,
            wasp = hole.declared_in.as_deref().unwrap_or("main.wasp"),
            line = hole.line,
        ),
    }
}

/// The path a fill run takes its analyzer baseline over: the file itself
/// when it exists, else the nearest existing directory above it.
fn scope_for(root: &Path, hole: &PendingHole) -> String {
    let mut path = root.join(&hole.file);
    while !path.exists() {
        match path.parent() {
            Some(parent) if parent.starts_with(root) => path = parent.to_path_buf(),
            _ => return ".".to_string(),
        }
    }
    let scope = relative(root, &path);
    if scope.is_empty() {
        ".".to_string()
    } else {
        scope
    }
}

/// Whether `hole` is still pending, re-scanned from disk.
pub fn still_pending(root: &Path, hole: &PendingHole) -> bool {
    let rescanned = match &hole.declared_in {
        Some(wasp) => {
            let path = root.join(wasp);
            let content = std::fs::read_to_string(&path).unwrap_or_default();
            wasp_holes(root, &path, &content)
        }
        None => {
            let content = std::fs::read_to_string(root.join(&hole.file)).unwrap_or_default();
            marker_holes(&hole.file, &content)
        }
    };
    rescanned
        .iter()
        .any(|h| h.file == hole.file && h.name == hole.name && h.export == hole.export)
}

/// What `vord agent fill` was asked for.
pub struct FillArgs {
    pub scope: String,
    /// Only holes with this name (or Wasp declaration name).
    pub only: Option<String>,
    pub limit: usize,
    pub model: Option<String>,
    pub max_turns: Option<u32>,
}

/// One attempted hole and how it ended.
pub struct Attempt {
    pub hole: PendingHole,
    pub outcome: RunOutcome,
    /// Checked on disk after the run, not taken from the model.
    pub filled: bool,
}

/// The holes `args` selects, in scan order.
pub fn select(root: &Path, args: &FillArgs) -> Vec<PendingHole> {
    scan(root, &args.scope)
        .into_iter()
        .filter(|hole| match &args.only {
            Some(name) => hole.name == *name || hole.name.ends_with(&format!(" {name}")),
            None => true,
        })
        .take(args.limit)
        .collect()
}

/// Runs one agent per selected hole. Stops early when a run fails (vord or
/// the model broke), since the next would fail the same way.
pub async fn fill(root: &Path, args: &FillArgs) -> anyhow::Result<Vec<Attempt>> {
    let mut attempts = Vec::new();
    for hole in select(root, args) {
        let outcome = agent::run(
            root,
            AgentArgs {
                task: task_for(&hole),
                scope: scope_for(root, &hole),
                rule: None,
                max_turns: args.max_turns,
                max_tokens: None,
                model: args.model.clone(),
                refactor: false,
            },
        )
        .await?;
        let failed = matches!(outcome, RunOutcome::Failed { .. });
        let filled = !still_pending(root, &hole);
        attempts.push(Attempt {
            hole,
            outcome,
            filled,
        });
        if failed {
            break;
        }
    }
    Ok(attempts)
}

/// One line per attempt, then the tally.
pub fn render_attempts(attempts: &[Attempt]) -> String {
    let mut out = String::new();
    for attempt in attempts {
        out.push_str(&format!(
            "{} {}  {}: {}\n",
            if attempt.filled { "filled " } else { "pending" },
            attempt.hole.file,
            display_name(&attempt.hole.name),
            attempt.outcome.describe().trim()
        ));
    }
    let filled = attempts.iter().filter(|a| a.filled).count();
    out.push_str(&format!("{filled} of {} hole(s) filled\n", attempts.len()));
    out
}

/// `vord agent fill`'s exit code: 0 when every attempted hole is filled, 1
/// when a run failed, 3 when holes remain.
pub fn exit_code(attempts: &[Attempt]) -> u8 {
    if attempts
        .iter()
        .any(|a| matches!(a.outcome, RunOutcome::Failed { .. }))
    {
        1
    } else if attempts.iter().all(|a| a.filled) {
        0
    } else {
        3
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn workspace(name: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!("vord-holes-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        root
    }

    fn write(root: &Path, path: &str, content: &str) {
        let path = root.join(path);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, content).unwrap();
    }

    const SERVICE: &str = "// Code generated by kthulu. DO NOT EDIT.\npackage order\n\nfunc (s *Service) Create(o Order) error {\n\t// vord:hole order-service-create\n\t// Add business logic here\n\t// vord:end-hole\n\treturn s.repo.Save(o)\n}\n";

    #[test]
    fn pending_marker_holes_are_listed_and_filled_ones_are_not() {
        let root = workspace("markers");
        write(&root, "internal/order/service.go", SERVICE);
        write(
            &root,
            "internal/user/service.go",
            &SERVICE
                .replace("order-service", "user-service")
                .replace("\t// Add business logic here\n", "\tif o.Total <= 0 { return ErrEmpty }\n"),
        );
        let found = scan(&root, ".");
        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!(found[0].file, "internal/order/service.go");
        assert_eq!(found[0].name, "order-service-create");
        assert_eq!((found[0].line, found[0].end_line), (5, 7));
        assert!(task_for(&found[0]).contains("`vord:hole order-service-create` marker (line 5)"));
        std::fs::remove_dir_all(&root).ok();
    }

    const MAIN_WASP: &str = r#"app todo {
  wasp: { version: "^0.15.0" },
  title: "todo"
}

route RootRoute { path: "/", to: MainPage }
page MainPage {
  component: import { MainPage } from "@src/MainPage"
}

query getTasks {
  fn: import { getTasks } from "@src/queries",
  entities: [Task]
}

action createTask {
  fn: import { createTask } from "@src/actions",
  entities: [Task]
}

job sendDigest {
  executor: PgBoss,
  perform: { fn: import sendDigest from "@server/jobs/digest" }
}
"#;

    #[test]
    fn wasp_operations_without_an_implementation_are_holes() {
        let root = workspace("wasp");
        write(&root, "app/main.wasp", MAIN_WASP);
        write(&root, "app/src/MainPage.tsx", "export function MainPage() { return null }\n");
        write(&root, "app/src/queries.ts", "export const getTasks = async () => []\n");
        write(&root, "app/src/actions.ts", "export const deleteTask = async () => {}\n");
        // Generated output is never a place to look for holes.
        write(&root, "app/.wasp/out/x.ts", "// vord:hole nope\n// vord:end-hole\n");

        let found = scan(&root, ".");
        let summary: Vec<(&str, &str, &str)> = found
            .iter()
            .map(|h| (h.name.as_str(), h.file.as_str(), h.reason.as_str()))
            .collect();
        assert_eq!(
            summary,
            [
                ("action createTask", "app/src/actions.ts", "no export `createTask`"),
                ("job sendDigest", "app/src/server/jobs/digest.ts", "file does not exist"),
            ]
        );
        assert_eq!(found[0].declared_in.as_deref(), Some("app/main.wasp"));
        assert_eq!(found[0].line, 17);
        assert!(task_for(&found[1]).contains("Do not edit `app/main.wasp`"));

        // Implementing it closes the hole, checked from disk.
        assert!(still_pending(&root, &found[0]));
        write(&root, "app/src/actions.ts", "export const createTask = async () => {}\n");
        assert!(!still_pending(&root, &found[0]));
        write(&root, "app/src/server/jobs/digest.ts", "export default async function () {}\n");
        assert!(scan(&root, ".").is_empty());
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn fill_selects_by_name_and_limit_and_scopes_to_what_exists() {
        let root = workspace("select");
        write(&root, "a.go", SERVICE);
        write(&root, "b.go", &SERVICE.replace("order-service-create", "billing-charge"));
        let args = |only: Option<&str>, limit| FillArgs {
            scope: ".".into(),
            only: only.map(String::from),
            limit,
            model: None,
            max_turns: None,
        };
        assert_eq!(select(&root, &args(None, 10)).len(), 2);
        assert_eq!(select(&root, &args(None, 1)).len(), 1);
        let only = select(&root, &args(Some("billing-charge"), 10));
        assert_eq!(only.len(), 1);
        assert_eq!(only[0].file, "b.go");
        assert_eq!(scope_for(&root, &only[0]), "b.go");

        let missing = PendingHole {
            file: "src/server/jobs/digest.ts".into(),
            ..only[0].clone()
        };
        assert_eq!(scope_for(&root, &missing), ".");
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn rendering_names_every_hole_and_the_tally() {
        let root = workspace("render");
        write(&root, "a.go", SERVICE);
        let text = render_text(&scan(&root, "."));
        assert!(text.contains("a.go:5-7  hole order-service-create"), "{text}");
        assert!(text.ends_with("1 pending hole(s)\n"));
        assert!(render_text(&[]).starts_with("No pending holes"));
        std::fs::remove_dir_all(&root).ok();
    }
}
