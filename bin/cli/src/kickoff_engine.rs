//! `vord kickoff --engine`: scaffold with a real generator, then make the
//! result governed from its first commit.
//!
//! vord does not reimplement Kthulu, Ferrum or Wasp. It runs the engine's
//! own CLI — deterministic generation is the engine's job — and then adds
//! what makes the output safe to hand to an agent:
//!
//! - `vord-policy.toml` and the Claude Code hook (`vord hook install`), so the
//!   first agent in the repository is already gated;
//! - `.vord/generated.json`, listing every file the engine marked as
//!   generated (a `vord:hole` region, or a standard `Code generated … DO NOT
//!   EDIT` / `@generated` header) with the command that regenerates it, so the
//!   write gate sends hand edits of generated structure back to the
//!   blueprint;
//! - a Gherkin scaffold for the scenarios the blueprint cannot express.
//!
//! Files an engine writes *without* such a marker are starter code the
//! project owns, and stay freely editable. An engine opts into protection
//! file by file by marking it — nothing is locked by guesswork.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;

use vord_cli::generated::{GeneratedFile, Manifest};

/// A scaffolding engine vord knows how to drive.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Engine {
    /// pmaojo/kthulu-go: Go modular monolith from `kthulu-plan.yaml`.
    Kthulu,
    /// pmaojo/ferrum: Rust + React hexagonal app from a `grafo.yaml`.
    Ferrum,
    /// wasp-lang/wasp: React + Node + Prisma app from `main.wasp`.
    Wasp,
    /// copier-org/copier: any Jinja project template; `copier update` is the
    /// regeneration. The blueprint is the template path or git URL.
    Copier,
    /// OpenAPI Generator: client/server code from an OpenAPI spec (the
    /// blueprint), for the generator named by `--generator`.
    OpenApi,
}

impl Engine {
    pub fn parse(raw: &str) -> anyhow::Result<Self> {
        match raw.to_ascii_lowercase().as_str() {
            "kthulu" => Ok(Self::Kthulu),
            "ferrum" => Ok(Self::Ferrum),
            "wasp" => Ok(Self::Wasp),
            "copier" => Ok(Self::Copier),
            "openapi" => Ok(Self::OpenApi),
            other => anyhow::bail!("unknown engine {other:?}. Supported engines: kthulu, ferrum, wasp, copier, openapi"),
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::Kthulu => "kthulu",
            Self::Ferrum => "ferrum",
            Self::Wasp => "wasp",
            Self::Copier => "copier",
            Self::OpenApi => "openapi",
        }
    }

    /// The executable the engine is run through.
    fn executable(self) -> &'static str {
        match self {
            Self::OpenApi => "openapi-generator-cli",
            other => other.name(),
        }
    }

    /// A pinned, non-interactive install, when one exists. Wasp's installer
    /// is a piped shell script, which vord does not run on its own.
    pub fn install_argv(self) -> Option<Vec<&'static str>> {
        match self {
            Self::Kthulu => Some(vec!["go", "install", "github.com/pmaojo/kthulu-go/cmd/kthulu@latest"]),
            Self::Ferrum => Some(vec!["cargo", "install", "--git", "https://github.com/pmaojo/ferrum", "ferrum"]),
            Self::Wasp => None,
            Self::Copier => Some(vec!["uv", "tool", "install", "copier==9.17.0"]),
            Self::OpenApi => Some(vec!["npm", "install", "-g", "@openapitools/openapi-generator-cli"]),
        }
    }

    fn install_hint(self) -> &'static str {
        match self {
            Self::Kthulu => "go install github.com/pmaojo/kthulu-go/cmd/kthulu@latest",
            Self::Ferrum => "cargo install --git https://github.com/pmaojo/ferrum ferrum",
            Self::Wasp => "curl -sSL https://get.wasp.sh/installer.sh | sh",
            Self::Copier => "uv tool install copier==9.17.0",
            Self::OpenApi => "npm install -g @openapitools/openapi-generator-cli (needs a JDK)",
        }
    }
}

/// What to generate and where.
pub struct EngineKickoff {
    pub engine: Engine,
    /// Project name, as the engine's own `new`/`create`/`init` takes it.
    pub name: String,
    /// The engine's blueprint, when generating from one.
    pub blueprint: Option<PathBuf>,
    /// Directory the project is created in (it becomes `<parent>/<name>`).
    pub parent: PathBuf,
    /// The engine executable; defaults to the engine's own name on PATH.
    pub program: Option<String>,
    /// OpenAPI Generator's generator name (`typescript-fetch`, `rust-axum`, ...).
    pub generator: Option<String>,
    /// Install the engine when it is not on PATH, instead of only saying how.
    pub install: bool,
}

/// One engine invocation: program, arguments, working directory.
#[derive(Debug, PartialEq, Eq)]
pub struct Step {
    pub program: String,
    pub args: Vec<String>,
    pub cwd: PathBuf,
}

impl EngineKickoff {
    pub fn project_dir(&self) -> PathBuf {
        self.parent.join(&self.name)
    }

    fn program(&self) -> String {
        self.program
            .clone()
            .unwrap_or_else(|| self.engine.executable().to_string())
    }

    /// Why this request cannot run, before anything is executed.
    pub fn validate(&self) -> anyhow::Result<()> {
        match self.engine {
            Engine::Copier if self.blueprint.is_none() => {
                anyhow::bail!("engine copier needs --blueprint <template path or git URL>")
            }
            Engine::OpenApi if self.blueprint.is_none() || self.generator.is_none() => {
                anyhow::bail!("engine openapi needs --blueprint <openapi spec> and --generator <name>, e.g. typescript-fetch")
            }
            _ => Ok(()),
        }
    }

    /// Every command that would run, install included, as text: `--plan`.
    pub fn plan(&self) -> Vec<String> {
        let mut lines = Vec::new();
        if let Some(argv) = self.engine.install_argv() {
            if self.install {
                lines.push(format!("(if {} is missing) {}", self.program(), argv.join(" ")));
            }
        }
        for step in self.steps() {
            lines.push(format!("{}: {} {}", step.cwd.display(), step.program, step.args.join(" ")));
        }
        lines
    }

    fn blueprint_arg(&self) -> Option<String> {
        self.blueprint.as_ref().map(|path| {
            std::fs::canonicalize(path)
                .unwrap_or_else(|_| path.clone())
                .display()
                .to_string()
        })
    }

    /// The engine commands, in order. Pure, so the exact invocation is
    /// testable without the engine installed.
    pub fn steps(&self) -> Vec<Step> {
        let program = self.program();
        let mut steps = Vec::new();
        match self.engine {
            Engine::Kthulu => {
                // `--skip-postgen`: no `go mod tidy`/`go test` side trip during
                // scaffolding; the agent's first test run does that under the
                // gate.
                let mut args = vec![
                    "create".to_string(),
                    self.name.clone(),
                    "--output".to_string(),
                    self.project_dir().display().to_string(),
                    "--skip-postgen".to_string(),
                ];
                if let Some(plan) = self.blueprint_arg() {
                    args.extend(["--from-plan".to_string(), plan]);
                }
                steps.push(Step { program, args, cwd: self.parent.clone() });
            }
            Engine::Ferrum => {
                steps.push(Step {
                    program: program.clone(),
                    args: vec!["init".to_string(), self.name.clone()],
                    cwd: self.parent.clone(),
                });
                if let Some(graph) = self.blueprint_arg() {
                    steps.push(Step {
                        program,
                        args: vec!["compile".to_string(), graph, "--output".to_string(), ".".to_string()],
                        cwd: self.project_dir(),
                    });
                }
            }
            Engine::Wasp => {
                steps.push(Step {
                    program,
                    args: vec!["new".to_string(), self.name.clone()],
                    cwd: self.parent.clone(),
                });
            }
            Engine::Copier => {
                let mut args = vec!["copy".to_string(), "--defaults".to_string(), "--trust".to_string()];
                args.extend(self.blueprint_arg());
                args.push(self.project_dir().display().to_string());
                steps.push(Step { program, args, cwd: self.parent.clone() });
            }
            Engine::OpenApi => {
                let mut args = vec!["generate".to_string(), "-i".to_string()];
                args.extend(self.blueprint_arg());
                args.extend(["-g".to_string(), self.generator.clone().unwrap_or_default()]);
                args.extend(["-o".to_string(), self.project_dir().display().to_string()]);
                steps.push(Step { program, args, cwd: self.parent.clone() });
            }
        }
        steps
    }

    /// The command recorded in the manifest as how to regenerate.
    pub fn regenerate_command(&self) -> String {
        let blueprint = self
            .blueprint
            .as_ref()
            .and_then(|p| p.file_name())
            .map(|f| f.to_string_lossy().to_string());
        match (self.engine, blueprint) {
            (Engine::Kthulu, Some(plan)) => format!("kthulu create {} --from-plan {plan}", self.name),
            (Engine::Kthulu, None) => "kthulu generate".to_string(),
            (Engine::Ferrum, Some(graph)) => format!("ferrum compile {graph} --output ."),
            (Engine::Ferrum, None) => "ferrum compile <grafo.yaml> --output .".to_string(),
            (Engine::Wasp, _) => "wasp compile".to_string(),
            (Engine::Copier, _) => "copier update --defaults --trust".to_string(),
            (Engine::OpenApi, spec) => format!(
                "openapi-generator-cli generate -i {} -g {} -o .",
                spec.unwrap_or_else(|| "<spec>".into()),
                self.generator.as_deref().unwrap_or("<generator>")
            ),
        }
    }
}

/// Is `program` an executable file in one of the PATH directories?
fn on_path(program: &str) -> bool {
    std::env::var_os("PATH")
        .map(|paths| std::env::split_paths(&paths).any(|dir| dir.join(program).is_file()))
        .unwrap_or(false)
}

/// Directories never walked when listing what an engine produced.
const SKIP_DIRS: &[&str] = &[".git", "node_modules", "target", ".wasp", ".vord", "vendor", "dist"];

fn list_files(root: &Path) -> BTreeSet<String> {
    fn walk(root: &Path, dir: &Path, out: &mut BTreeSet<String>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let name = entry.file_name();
            if path.is_dir() {
                if !SKIP_DIRS.contains(&name.to_string_lossy().as_ref()) {
                    walk(root, &path, out);
                }
            } else if let Ok(relative) = path.strip_prefix(root) {
                out.insert(relative.to_string_lossy().replace('\\', "/"));
            }
        }
    }
    let mut out = BTreeSet::new();
    walk(root, root, &mut out);
    out
}

/// Has the engine marked this file as generated?
pub fn is_marked_generated(content: &str) -> bool {
    let head: String = content.lines().take(10).collect::<Vec<_>>().join("\n");
    content.contains(vord_agent_policy::generated::HOLE_OPEN)
        || (head.contains("Code generated") && head.contains("DO NOT EDIT"))
        || head.contains("@generated")
}

/// What `run` did, for the caller to report.
#[derive(Debug)]
pub struct KickoffReport {
    pub project_dir: PathBuf,
    pub created: usize,
    pub generated: usize,
}

/// Runs the engine, then layers vord's governance on top of its output.
pub fn run(kickoff: &EngineKickoff) -> anyhow::Result<KickoffReport> {
    kickoff.validate()?;
    let project_dir = kickoff.project_dir();
    let before = list_files(&project_dir);
    if kickoff.install && kickoff.program.is_none() && !on_path(&kickoff.program()) {
        let Some(argv) = kickoff.engine.install_argv() else {
            anyhow::bail!("install {} yourself: {}", kickoff.program(), kickoff.engine.install_hint());
        };
        let status = Command::new(argv[0]).args(&argv[1..]).status().map_err(|e| {
            anyhow::anyhow!("could not run `{}` ({e}). Install the engine manually: {}", argv.join(" "), kickoff.engine.install_hint())
        })?;
        if !status.success() {
            anyhow::bail!("`{}` failed ({status})", argv.join(" "));
        }
    }

    for step in kickoff.steps() {
        let status = Command::new(&step.program)
            .args(&step.args)
            .current_dir(&step.cwd)
            .status()
            .map_err(|e| {
                anyhow::anyhow!(
                    "could not run {} ({e}). Install it with: {}",
                    step.program,
                    kickoff.engine.install_hint()
                )
            })?;
        if !status.success() {
            anyhow::bail!("`{} {}` failed ({status})", step.program, step.args.join(" "));
        }
    }
    if !project_dir.is_dir() {
        anyhow::bail!(
            "{} finished but {} does not exist",
            kickoff.engine.name(),
            project_dir.display()
        );
    }

    let created: Vec<String> = list_files(&project_dir).difference(&before).cloned().collect();
    let mut manifest = Manifest::load(&project_dir);
    let source = kickoff
        .blueprint
        .as_ref()
        .and_then(|p| p.file_name())
        .map(|f| f.to_string_lossy().to_string());
    let regenerate = kickoff.regenerate_command();
    for relative in &created {
        let Ok(content) = std::fs::read_to_string(project_dir.join(relative)) else {
            continue; // binary output is never hand-edited through a text tool
        };
        // OpenAPI Generator output is wholly the spec's; its ignore file lists
        // what the project owns instead.
        let wholly_generated = kickoff.engine == Engine::OpenApi && relative != ".openapi-generator-ignore";
        if wholly_generated || is_marked_generated(&content) {
            manifest.files.insert(
                relative.clone(),
                GeneratedFile {
                    engine: kickoff.engine.name().to_string(),
                    source: source.clone(),
                    regenerate: Some(regenerate.clone()),
                },
            );
        }
    }
    manifest.save(&project_dir)?;

    crate::hook_install::install(&project_dir, crate::hook_install::DEFAULT_HOOK_COMMAND)?;
    if kickoff.engine == Engine::Wasp {
        protect_wasp_output(&project_dir, "")?;
    }
    crate::kickoff::write_gherkin_scaffold(&project_dir, "app", &format!("{} application", kickoff.name))?;
    ignore_session_state(&project_dir)?;

    Ok(KickoffReport {
        project_dir,
        created: created.len(),
        generated: manifest.files.len(),
    })
}

/// A backend engine and a Wasp frontend generated side by side, joined by one
/// OpenAPI contract: the backend serves it, the frontend's typed client is
/// generated from it, and neither side hand-writes the API layer.
pub struct FullstackKickoff {
    pub backend: Engine,
    pub name: String,
    /// The backend engine's blueprint.
    pub blueprint: Option<PathBuf>,
    pub parent: PathBuf,
    pub install: bool,
}

/// The command that regenerates the frontend's typed API client.
pub const CLIENT_REGENERATE: &str = "npx openapi-typescript ../contract/openapi.yaml -o src/api/schema.ts";

/// Backend into `<name>/backend`, Wasp into `<name>/frontend`, one governed
/// workspace at `<name>`. Only the backend languages a Wasp frontend can sit
/// on are accepted.
pub fn run_fullstack(kickoff: &FullstackKickoff) -> anyhow::Result<KickoffReport> {
    if kickoff.backend == Engine::Wasp {
        anyhow::bail!("--frontend wasp already is a full-stack engine; pick a backend engine: ferrum (Rust) or kthulu (Go)");
    }
    let root = kickoff.parent.join(&kickoff.name);
    std::fs::create_dir_all(&root)?;
    let mut created = 0;
    for (engine, dir, blueprint) in [
        (kickoff.backend, "backend", kickoff.blueprint.clone()),
        (Engine::Wasp, "frontend", None),
    ] {
        let part = EngineKickoff {
            engine,
            name: dir.to_string(),
            blueprint,
            parent: root.clone(),
            program: None,
            generator: None,
            install: kickoff.install,
        };
        created += run(&part)?.created;
    }

    // One manifest and one hook at the workspace root, where the agent works.
    let mut manifest = Manifest::load(&root);
    for dir in ["backend", "frontend"] {
        let part = root.join(dir);
        for (file, mut entry) in Manifest::load(&part).files {
            entry.regenerate = entry.regenerate.map(|command| format!("cd {dir} && {command}"));
            manifest.files.insert(format!("{dir}/{file}"), entry);
        }
        // The workspace root governs both halves; per-part governance is noise.
        std::fs::remove_dir_all(part.join(".vord")).ok();
        std::fs::remove_dir_all(part.join(".claude")).ok();
        std::fs::remove_file(part.join(vord_cli::hook::POLICY_FILE)).ok();
        std::fs::remove_file(part.join(".gitignore")).ok();
    }
    std::fs::create_dir_all(root.join("contract"))?;
    let contract = root.join("contract/openapi.yaml");
    if !contract.exists() {
        std::fs::write(
            &contract,
            format!(
                "openapi: 3.0.3\ninfo:\n  title: {}\n  version: 0.1.0\npaths: {{}}\n",
                kickoff.name
            ),
        )?;
        created += 1;
    }
    manifest.save(&root)?;
    crate::hook_install::install(&root, crate::hook_install::DEFAULT_HOOK_COMMAND)?;
    protect_wasp_output(&root, "frontend/")?;
    ignore_session_state(&root)?;
    std::fs::write(
        root.join("contract/README.md"),
        format!(
            "The API contract shared by `backend/` and `frontend/`.\n\nChange `openapi.yaml`, then regenerate the frontend client with:\n\n    cd frontend && {CLIENT_REGENERATE}\n"
        ),
    )?;
    Ok(KickoffReport { project_dir: root, created, generated: manifest.files.len() })
}

/// Wasp regenerates its whole full-stack output into `.wasp/` on every
/// compile; nothing there is ever edited by hand.
fn protect_wasp_output(project_dir: &Path, prefix: &str) -> anyhow::Result<()> {
    let policy = project_dir.join(vord_cli::hook::POLICY_FILE);
    let mut content = std::fs::read_to_string(&policy).unwrap_or_default();
    let pattern = format!("{prefix}.wasp/**");
    if content.contains(&format!("pattern = \"{pattern}\"")) {
        return Ok(());
    }
    content.push_str(&format!(
        "\n# Added by `vord kickoff`: Wasp regenerates everything under\n\
         # .wasp/ from main.wasp on each compile.\n\
         [[protected_path]]\n\
         pattern = \"{pattern}\"\n\
         reason = \"Generated by Wasp from main.wasp — change main.wasp or src/, then run `wasp compile`.\"\n",
    ));
    std::fs::write(&policy, content)?;
    Ok(())
}

/// Per-session analyzer baselines (dsh-vord) are local state, not source.
fn ignore_session_state(project_dir: &Path) -> anyhow::Result<()> {
    let gitignore = project_dir.join(".gitignore");
    let mut content = std::fs::read_to_string(&gitignore).unwrap_or_default();
    if content.lines().any(|line| line.trim() == ".vord/sessions/") {
        return Ok(());
    }
    if !content.is_empty() && !content.ends_with('\n') {
        content.push('\n');
    }
    content.push_str(".vord/sessions/\n");
    std::fs::write(&gitignore, content)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kickoff(engine: Engine, blueprint: Option<&str>) -> EngineKickoff {
        EngineKickoff {
            engine,
            name: "shop".into(),
            blueprint: blueprint.map(PathBuf::from),
            parent: PathBuf::from("/work"),
            program: None,
            generator: None,
            install: false,
        }
    }

    #[test]
    fn kthulu_creates_from_the_plan_without_post_generation_side_trips() {
        let steps = kickoff(Engine::Kthulu, Some("/plans/kthulu-plan.yaml")).steps();
        assert_eq!(steps.len(), 1);
        assert_eq!(steps[0].program, "kthulu");
        assert_eq!(
            steps[0].args,
            ["create", "shop", "--output", "/work/shop", "--skip-postgen", "--from-plan", "/plans/kthulu-plan.yaml"]
        );
    }

    #[test]
    fn ferrum_inits_then_compiles_the_graph_inside_the_project() {
        let steps = kickoff(Engine::Ferrum, Some("/plans/users.yaml")).steps();
        assert_eq!(steps[0].args, ["init", "shop"]);
        assert_eq!(steps[0].cwd, PathBuf::from("/work"));
        assert_eq!(steps[1].args, ["compile", "/plans/users.yaml", "--output", "."]);
        assert_eq!(steps[1].cwd, PathBuf::from("/work/shop"));
        assert_eq!(kickoff(Engine::Ferrum, None).steps().len(), 1, "no graph, no compile");
    }

    #[test]
    fn wasp_runs_wasp_new() {
        let steps = kickoff(Engine::Wasp, None).steps();
        assert_eq!(steps[0].args, ["new", "shop"]);
        assert_eq!(kickoff(Engine::Wasp, None).regenerate_command(), "wasp compile");
    }

    #[test]
    fn only_files_the_engine_marked_count_as_generated() {
        assert!(is_marked_generated("// Code generated by kthulu. DO NOT EDIT.\npackage x\n"));
        assert!(is_marked_generated("fn f() {\n  // vord:hole body\n  // vord:end-hole\n}\n"));
        assert!(is_marked_generated("# @generated by ferrum\n"));
        assert!(!is_marked_generated("package main\n\nfunc main() {}\n"), "starter code stays the project's");
    }

    #[test]
    fn unknown_engines_are_rejected_by_name() {
        assert!(Engine::parse("Kthulu").is_ok());
        assert!(Engine::parse("rails").unwrap_err().to_string().contains("kthulu, ferrum, wasp"));
    }

    #[test]
    fn a_fake_engine_run_writes_the_manifest_policy_and_scaffold() {
        let parent = std::env::temp_dir().join(format!("vord-kickoff-engine-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&parent);
        std::fs::create_dir_all(&parent).unwrap();
        // A stand-in engine: `wasp new shop` creates one marked and one
        // unmarked file.
        let fake = parent.join("fake-engine.sh");
        std::fs::write(
            &fake,
            "#!/bin/sh\nmkdir -p \"$2/src\"\nprintf '// @generated\\nexport const a = 1\\n' > \"$2/src/gen.ts\"\nprintf 'export const b = 2\\n' > \"$2/src/own.ts\"\n",
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let run_kickoff = EngineKickoff {
            engine: Engine::Wasp,
            name: "shop".into(),
            blueprint: None,
            parent: parent.clone(),
            program: Some(fake.display().to_string()),
            generator: None,
            install: false,
        };

        let report = run(&run_kickoff).unwrap();

        let dir = parent.join("shop");
        assert_eq!(report.created, 2);
        let manifest = Manifest::load(&dir);
        assert_eq!(manifest.files.keys().collect::<Vec<_>>(), ["src/gen.ts"]);
        assert_eq!(manifest.files["src/gen.ts"].regenerate.as_deref(), Some("wasp compile"));
        let policy = std::fs::read_to_string(dir.join("vord-policy.toml")).unwrap();
        assert!(policy.contains("pattern = \".wasp/**\""));
        let parsed = vord_cli::hook::load_policy(&dir).expect("the appended policy still parses");
        let denied = parsed.evaluate_with_evidence(".wasp/out/server/src/app.ts", &[], Default::default(), true);
        assert!(denied.is_denied(), "Wasp's regenerated output is off-limits: {denied:?}");
        assert!(dir.join(".claude/settings.json").exists());
        assert!(dir.join("features/app.feature").exists());
        assert!(std::fs::read_to_string(dir.join(".gitignore")).unwrap().contains(".vord/sessions/"));
        std::fs::remove_dir_all(&parent).ok();
    }

    #[test]
    fn copier_and_openapi_steps_and_validation() {
        let mut k = kickoff(Engine::Copier, Some("gh:org/tpl"));
        let steps = k.steps();
        assert_eq!(steps[0].program, "copier");
        assert_eq!(&steps[0].args[..3], ["copy", "--defaults", "--trust"]);
        assert_eq!(k.regenerate_command(), "copier update --defaults --trust");
        assert!(kickoff(Engine::Copier, None).validate().is_err());

        assert!(kickoff(Engine::OpenApi, Some("api.yaml")).validate().is_err(), "needs a generator");
        k = kickoff(Engine::OpenApi, Some("api.yaml"));
        k.generator = Some("typescript-fetch".into());
        k.validate().unwrap();
        assert_eq!(k.steps()[0].program, "openapi-generator-cli");
        assert!(k.regenerate_command().contains("-g typescript-fetch"));
    }

    #[test]
    fn plan_lists_the_install_only_when_asked() {
        let mut k = kickoff(Engine::Copier, Some("gh:org/tpl"));
        assert_eq!(k.plan().len(), 1);
        k.install = true;
        assert!(k.plan()[0].contains("uv tool install copier==9.17.0"));
        assert!(Engine::Wasp.install_argv().is_none(), "no piped shell installers");
    }

    #[test]
    fn fullstack_refuses_wasp_as_backend() {
        let err = run_fullstack(&FullstackKickoff {
            backend: Engine::Wasp,
            name: "shop".into(),
            blueprint: None,
            parent: PathBuf::from("/nonexistent"),
            install: false,
        })
        .unwrap_err();
        assert!(err.to_string().contains("ferrum"), "{err}");
    }
}
