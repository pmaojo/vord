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
    /// The project's test command. When set, each hole goes RED → GREEN
    /// (see [`TestGate`]); when not, the hole is filled in one run.
    pub tests: Option<TestGate>,
}

/// One attempted hole and how it ended.
pub struct Attempt {
    pub hole: PendingHole,
    pub outcome: RunOutcome,
    /// Checked on disk after the run, not taken from the model.
    pub filled: bool,
    /// Why the RED → GREEN gate refused this hole, when it did. A refused
    /// hole is not done even if code landed in it.
    pub refused: Option<String>,
}

impl Attempt {
    fn accepted(&self) -> bool {
        self.filled && self.refused.is_none()
    }
}

/// Test-first filling, enforced by running the tests rather than by asking
/// the model to follow TDD. For each hole:
///
/// 1. the suite must pass before anything is written, or a red result later
///    would prove nothing;
/// 2. **RED**: one run writes a test for the hole and nothing else. It is
///    accepted only if the suite now fails, the hole is still pending, and
///    some file changed;
/// 3. **GREEN**: one run fills the hole. It is accepted only if the hole is
///    filled, the suite passes, and every file the RED run wrote is
///    byte-for-byte unchanged: an assertion changed to pass is a behaviour
///    change, and belongs in the spec.
///
/// Whether a failure is an assertion rather than a compile error is not
/// checked: that needs per-language knowledge of test output.
#[derive(Clone, Debug)]
pub struct TestGate {
    /// Run with `sh -c` at the repository root; exit 0 means green.
    pub command: String,
    pub timeout: std::time::Duration,
}

/// Default for [`TestGate::timeout`] when `vord.toml` does not set
/// `command_timeout_secs`.
pub const TEST_TIMEOUT_SECS: u64 = 300;

/// What one run of the test command said.
enum TestRun {
    Green,
    Red(String),
}

impl TestGate {
    fn run(&self, root: &Path) -> anyhow::Result<TestRun> {
        use std::process::{Command, Stdio};
        let mut child = Command::new("sh")
            .arg("-c")
            .arg(&self.command)
            .current_dir(root)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| anyhow::anyhow!("could not run test command `{}`: {e}", self.command))?;
        let started = std::time::Instant::now();
        while child.try_wait()?.is_none() {
            if started.elapsed() > self.timeout {
                child.kill().ok();
                child.wait().ok();
                return Ok(TestRun::Red(format!(
                    "timed out after {}s",
                    self.timeout.as_secs()
                )));
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        let output = child.wait_with_output()?;
        if output.status.success() {
            return Ok(TestRun::Green);
        }
        let text = format!(
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        let lines: Vec<&str> = text.lines().filter(|l| !l.trim().is_empty()).collect();
        Ok(TestRun::Red(
            lines[lines.len().saturating_sub(8)..].join(" | "),
        ))
    }
}

/// Content fingerprint of every file under `root` the hole scan would look
/// at, so a phase's writes can be found and later held fixed.
type Snapshot = std::collections::BTreeMap<String, u64>;

fn snapshot(root: &Path) -> Snapshot {
    use std::hash::{Hash, Hasher};
    ignore::WalkBuilder::new(root)
        .hidden(false)
        .filter_entry(|entry| {
            !matches!(
                entry.file_name().to_str(),
                Some(".git" | ".wasp" | "node_modules" | "target")
            ) && !entry
                .file_name()
                .to_str()
                .is_some_and(|name| name.starts_with(".vord"))
        })
        .build()
        .flatten()
        .filter(|entry| entry.file_type().is_some_and(|t| t.is_file()))
        .filter_map(|entry| {
            let bytes = std::fs::read(entry.path()).ok()?;
            let mut hasher = std::collections::hash_map::DefaultHasher::new();
            bytes.hash(&mut hasher);
            Some((relative(root, entry.path()), hasher.finish()))
        })
        .collect()
}

/// Paths whose content differs between two snapshots, added ones included.
fn changed(before: &Snapshot, after: &Snapshot) -> Vec<String> {
    after
        .iter()
        .filter(|(path, hash)| before.get(*path) != Some(hash))
        .map(|(path, _)| path.clone())
        .collect()
}

/// The RED run's task: a failing test for the hole, and nothing in the hole.
pub fn red_task_for(hole: &PendingHole, command: &str) -> String {
    format!(
        "Write a test for the hole `{name}` in `{file}`, and nothing else. Read the hole, the \
         code around it and the blueprint to work out what it must do, then add a test that \
         calls that code and asserts the behaviour it must have. The test must fail now, on an \
         assertion, because the hole is still empty: stub nothing, fill nothing. Do not write \
         inside the hole and do not change generated code. `{command}` runs the tests; run it \
         and make sure your new test is the one failing.",
        name = display_name(&hole.name),
        file = hole.file,
    )
}

/// The GREEN run's task: the fill task, held to the RED run's tests.
pub fn green_task_for(hole: &PendingHole, command: &str, tests: &[String]) -> String {
    format!(
        "{fill} A failing test already says what it must do ({tests}); write the minimum that \
         makes `{command}` pass. Do not change those test files: changing an assertion is a \
         behaviour change, and vord refuses the fill if any of them differs.",
        fill = task_for(hole),
        tests = tests
            .iter()
            .map(|t| format!("`{t}`"))
            .collect::<Vec<_>>()
            .join(", "),
    )
}

/// Runs the model on one task. The seam lets tests drive fill without one.
#[allow(async_fn_in_trait)]
pub trait HoleAgent {
    async fn run(&mut self, root: &Path, args: AgentArgs) -> anyhow::Result<RunOutcome>;
}

/// The real agent: one `vord agent` run per task.
pub struct LiveAgent;

impl HoleAgent for LiveAgent {
    async fn run(&mut self, root: &Path, args: AgentArgs) -> anyhow::Result<RunOutcome> {
        agent::run(root, args).await
    }
}

fn agent_args(root: &Path, hole: &PendingHole, args: &FillArgs, task: String) -> AgentArgs {
    AgentArgs {
        task,
        scope: scope_for(root, hole),
        rule: None,
        max_turns: args.max_turns,
        max_tokens: None,
        model: args.model.clone(),
        refactor: false,
    }
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

/// Runs one agent per selected hole (two with a [`TestGate`]: RED, then
/// GREEN). Stops early when a run fails (vord or the model broke), or when
/// the suite is red before a hole is started, since the next hole would
/// fail the same way.
pub async fn fill(root: &Path, args: &FillArgs) -> anyhow::Result<Vec<Attempt>> {
    fill_with(root, args, &mut LiveAgent).await
}

pub async fn fill_with(
    root: &Path,
    args: &FillArgs,
    model: &mut impl HoleAgent,
) -> anyhow::Result<Vec<Attempt>> {
    let mut attempts = Vec::new();
    for hole in select(root, args) {
        let attempt = match &args.tests {
            None => {
                let task = task_for(&hole);
                let outcome = model.run(root, agent_args(root, &hole, args, task)).await?;
                let filled = !still_pending(root, &hole);
                Attempt {
                    hole,
                    outcome,
                    filled,
                    refused: None,
                }
            }
            Some(gate) => red_green(root, args, gate, hole, model).await?,
        };
        let stop = matches!(attempt.outcome, RunOutcome::Failed { .. })
            || attempt
                .refused
                .as_deref()
                .is_some_and(|r| r.starts_with(RED_BEFORE));
        attempts.push(attempt);
        if stop {
            break;
        }
    }
    Ok(attempts)
}

const RED_BEFORE: &str = "the tests fail before the hole is started";

async fn red_green(
    root: &Path,
    args: &FillArgs,
    gate: &TestGate,
    hole: PendingHole,
    model: &mut impl HoleAgent,
) -> anyhow::Result<Attempt> {
    let refuse = |hole, outcome, filled, why: String| Attempt {
        hole,
        outcome,
        filled,
        refused: Some(why),
    };
    if let TestRun::Red(tail) = gate.run(root)? {
        let outcome = RunOutcome::Completed {
            turns: 0,
            summary: None,
        };
        return Ok(refuse(
            hole,
            outcome,
            false,
            format!("{RED_BEFORE}: {tail}"),
        ));
    }

    let before_red = snapshot(root);
    let task = red_task_for(&hole, &gate.command);
    let outcome = model.run(root, agent_args(root, &hole, args, task)).await?;
    if matches!(outcome, RunOutcome::Failed { .. }) {
        return Ok(refuse(hole, outcome, false, "RED: the run failed".into()));
    }
    let after_red = snapshot(root);
    let tests = changed(&before_red, &after_red);
    if !still_pending(root, &hole) {
        return Ok(refuse(
            hole,
            outcome,
            true,
            "RED: the hole was filled before a failing test existed".into(),
        ));
    }
    if tests.is_empty() {
        return Ok(refuse(
            hole,
            outcome,
            false,
            "RED: no test was written".into(),
        ));
    }
    if let TestRun::Green = gate.run(root)? {
        return Ok(refuse(
            hole,
            outcome,
            false,
            format!(
                "RED: the tests still pass after writing {}",
                tests.join(", ")
            ),
        ));
    }

    let task = green_task_for(&hole, &gate.command, &tests);
    let outcome = model.run(root, agent_args(root, &hole, args, task)).await?;
    let filled = !still_pending(root, &hole);
    if matches!(outcome, RunOutcome::Failed { .. }) {
        return Ok(Attempt {
            hole,
            outcome,
            filled,
            refused: None,
        });
    }
    let after_green = snapshot(root);
    let touched: Vec<String> = tests
        .iter()
        .filter(|t| after_red.get(*t) != after_green.get(*t))
        .cloned()
        .collect();
    let refused = if !touched.is_empty() {
        Some(format!(
            "GREEN: changed the RED test(s) {}",
            touched.join(", ")
        ))
    } else if !filled {
        None
    } else if let TestRun::Red(tail) = gate.run(root)? {
        Some(format!("GREEN: the tests still fail: {tail}"))
    } else {
        None
    };
    Ok(Attempt {
        hole,
        outcome,
        filled,
        refused,
    })
}

/// One line per attempt, then the tally.
pub fn render_attempts(attempts: &[Attempt]) -> String {
    let mut out = String::new();
    for attempt in attempts {
        let label = if attempt.refused.is_some() {
            "refused"
        } else if attempt.filled {
            "filled "
        } else {
            "pending"
        };
        let detail = match &attempt.refused {
            Some(why) => why.clone(),
            None => attempt.outcome.describe().trim().to_string(),
        };
        out.push_str(&format!(
            "{label} {}  {}: {detail}\n",
            attempt.hole.file,
            display_name(&attempt.hole.name),
        ));
    }
    let filled = attempts.iter().filter(|a| a.accepted()).count();
    out.push_str(&format!("{filled} of {} hole(s) filled\n", attempts.len()));
    out
}

/// `vord agent fill`'s exit code: 0 when every attempted hole is filled
/// (and, under a [`TestGate`], passed RED → GREEN), 1 when a run failed, 3
/// when holes remain or were refused.
pub fn exit_code(attempts: &[Attempt]) -> u8 {
    if attempts
        .iter()
        .any(|a| matches!(a.outcome, RunOutcome::Failed { .. }))
    {
        1
    } else if attempts.iter().all(Attempt::accepted) {
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
        write(
            &root,
            "b.go",
            &SERVICE.replace("order-service-create", "billing-charge"),
        );
        let args = |only: Option<&str>, limit| FillArgs {
            scope: ".".into(),
            only: only.map(String::from),
            limit,
            model: None,
            max_turns: None,
            tests: None,
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

    /// Each run applies the next scripted set of writes, then reports done.
    struct Scripted {
        steps: Vec<Vec<(&'static str, String)>>,
        tasks: Vec<String>,
    }

    impl HoleAgent for Scripted {
        async fn run(&mut self, root: &Path, args: AgentArgs) -> anyhow::Result<RunOutcome> {
            self.tasks.push(args.task);
            for (path, content) in self.steps.remove(0) {
                write(root, path, &content);
            }
            Ok(RunOutcome::Completed {
                turns: 1,
                summary: None,
            })
        }
    }

    const FILLED: &str = "\tif o.Total <= 0 { return ErrEmpty }\n";

    /// The "suite" is a shell check: `spec.txt` names what the hole must
    /// contain, and the hole must contain it.
    fn tdd_args() -> FillArgs {
        FillArgs {
            scope: ".".into(),
            only: None,
            limit: 5,
            model: None,
            max_turns: None,
            tests: Some(TestGate {
                command: "test ! -f spec.txt || grep -qF \"$(cat spec.txt)\" a.go".into(),
                timeout: std::time::Duration::from_secs(10),
            }),
        }
    }

    fn filled_service() -> String {
        SERVICE.replace("\t// Add business logic here\n", FILLED)
    }

    #[tokio::test]
    async fn red_then_green_fills_the_hole() {
        let root = workspace("tdd-ok");
        write(&root, "a.go", SERVICE);
        let mut model = Scripted {
            steps: vec![
                vec![("spec.txt", "ErrEmpty".into())],
                vec![("a.go", filled_service())],
            ],
            tasks: vec![],
        };
        let attempts = fill_with(&root, &tdd_args(), &mut model).await.unwrap();
        assert_eq!(attempts.len(), 1);
        assert!(attempts[0].accepted(), "{:?}", attempts[0].refused);
        assert_eq!(exit_code(&attempts), 0);
        assert!(model.tasks[0].starts_with("Write a test for the hole `order-service-create`"));
        assert!(
            model.tasks[1].contains("(`spec.txt`)"),
            "{}",
            model.tasks[1]
        );
        std::fs::remove_dir_all(&root).ok();
    }

    #[tokio::test]
    async fn red_must_fail_and_must_not_fill() {
        let root = workspace("tdd-red");
        write(&root, "a.go", SERVICE);
        // A test that already passes proves nothing.
        let mut model = Scripted {
            steps: vec![vec![("spec.txt", "package order".into())]],
            tasks: vec![],
        };
        let attempts = fill_with(&root, &tdd_args(), &mut model).await.unwrap();
        let why = attempts[0].refused.as_deref().unwrap();
        assert!(why.starts_with("RED: the tests still pass"), "{why}");
        assert_eq!(exit_code(&attempts), 3);

        // Code before its test is refused even if it is right.
        std::fs::remove_file(root.join("spec.txt")).unwrap();
        let mut model = Scripted {
            steps: vec![vec![("a.go", filled_service())]],
            tasks: vec![],
        };
        let attempts = fill_with(&root, &tdd_args(), &mut model).await.unwrap();
        assert_eq!(
            attempts[0].refused.as_deref(),
            Some("RED: the hole was filled before a failing test existed")
        );
        std::fs::remove_dir_all(&root).ok();
    }

    #[tokio::test]
    async fn green_may_not_touch_the_red_test() {
        let root = workspace("tdd-green");
        write(&root, "a.go", SERVICE);
        // Fills the hole, then weakens the test to match.
        let mut model = Scripted {
            steps: vec![
                vec![("spec.txt", "ErrNegative".into())],
                vec![("a.go", filled_service()), ("spec.txt", "ErrEmpty".into())],
            ],
            tasks: vec![],
        };
        let attempts = fill_with(&root, &tdd_args(), &mut model).await.unwrap();
        assert!(attempts[0].filled);
        assert_eq!(
            attempts[0].refused.as_deref(),
            Some("GREEN: changed the RED test(s) spec.txt")
        );
        assert!(render_attempts(&attempts).contains("refused a.go"));
        assert!(render_attempts(&attempts).ends_with("0 of 1 hole(s) filled\n"));
        std::fs::remove_dir_all(&root).ok();
    }

    #[tokio::test]
    async fn a_red_suite_stops_before_any_hole_is_started() {
        let root = workspace("tdd-before");
        write(&root, "a.go", SERVICE);
        write(
            &root,
            "b.go",
            &SERVICE.replace("order-service-create", "billing-charge"),
        );
        write(&root, "spec.txt", "not there");
        let mut model = Scripted {
            steps: vec![],
            tasks: vec![],
        };
        let attempts = fill_with(&root, &tdd_args(), &mut model).await.unwrap();
        assert_eq!(attempts.len(), 1, "the second hole would fail the same way");
        assert!(
            attempts[0]
                .refused
                .as_deref()
                .unwrap()
                .starts_with(RED_BEFORE)
        );
        assert!(model.tasks.is_empty());
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn rendering_names_every_hole_and_the_tally() {
        let root = workspace("render");
        write(&root, "a.go", SERVICE);
        let text = render_text(&scan(&root, "."));
        assert!(
            text.contains("a.go:5-7  hole order-service-create"),
            "{text}"
        );
        assert!(text.ends_with("1 pending hole(s)\n"));
        assert!(render_text(&[]).starts_with("No pending holes"));
        std::fs::remove_dir_all(&root).ok();
    }
}
