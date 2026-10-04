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

/// What an engine can produce.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Capability {
    Backend,
    Frontend,
    /// Generates from a declarative blueprint/spec.
    SpecDriven,
    /// Generates from a built-in starter template.
    Template,
}

/// Everything vord knows about one scaffolding engine. Adding an engine is
/// adding one entry to [`ENGINES`] (plus its `Engine` variant and `steps`
/// arm); the CLI, the MCP tool schema and validation read from here.
#[derive(Debug, serde::Serialize)]
pub struct EngineSpec {
    /// Name used on `--engine` and in the manifest.
    pub name: &'static str,
    /// Default executable looked up on PATH.
    pub executable: &'static str,
    /// What the engine generates, as shown to users and agents.
    pub generates: &'static str,
    /// Lower-case language names (and aliases) that select this engine.
    pub languages: &'static [&'static str],
    pub capabilities: &'static [Capability],
    /// Pinned install command, when one exists (None: only the hint applies).
    pub install_argv: Option<&'static [&'static str]>,
    pub install_hint: &'static str,
    /// Regeneration command recorded in the manifest when a blueprint is
    /// given; `{name}` and `{blueprint}` (file name) are substituted.
    pub regenerate_with_blueprint: &'static str,
    /// Regeneration command when there is no blueprint. `{generator}` is
    /// the `--generator` name (`<generator>` when absent).
    pub regenerate_default: &'static str,
    /// True when every file the engine writes (bar its ignore file) belongs
    /// to the blueprint, so vord records all of it as generated. Wasp is
    /// protected through its `.wasp/` tree instead.
    pub all_output_generated: bool,
    /// Request arguments that must be present to kick off with this engine.
    pub required_args: &'static [&'static str],
    /// Named ready-to-run recipes: `(title, command)`.
    pub recipes: &'static [(&'static str, &'static str)],
}

impl EngineSpec {
    pub fn has(&self, capability: Capability) -> bool {
        self.capabilities.contains(&capability)
    }

    fn regenerate(&self, name: &str, blueprint: Option<&str>, generator: Option<&str>) -> String {
        let template = if blueprint.is_some() { self.regenerate_with_blueprint } else { self.regenerate_default };
        template
            .replace("{name}", name)
            .replace("{blueprint}", blueprint.unwrap_or("<spec>"))
            .replace("{generator}", generator.unwrap_or("<generator>"))
    }
}

/// The registry, in display order.
pub const ENGINES: &[EngineSpec] = &[
    EngineSpec {
        name: "kthulu",
        executable: "kthulu",
        generates: "Go",
        languages: &["go", "golang"],
        capabilities: &[Capability::Backend, Capability::SpecDriven],
        install_argv: Some(&["go", "install", "github.com/pmaojo/kthulu-go/cmd/kthulu@latest"]),
        install_hint: "go install github.com/pmaojo/kthulu-go/cmd/kthulu@latest",
        regenerate_with_blueprint: "kthulu create {name} --from-plan {blueprint}",
        regenerate_default: "kthulu generate",
        all_output_generated: false,
        required_args: &["name"],
        recipes: &[],
    },
    EngineSpec {
        name: "ferrum",
        executable: "ferrum",
        generates: "Rust + React",
        languages: &["rust", "rs"],
        capabilities: &[Capability::Backend, Capability::Frontend, Capability::SpecDriven],
        install_argv: Some(&["cargo", "install", "--git", "https://github.com/pmaojo/ferrum", "ferrum-cli"]),
        install_hint: "cargo install --git https://github.com/pmaojo/ferrum ferrum-cli",
        regenerate_with_blueprint: "ferrum compile gen/{blueprint} --output .",
        regenerate_default: "ferrum compile <grafo.yaml> --output .",
        all_output_generated: false,
        required_args: &["name"],
        recipes: &[],
    },
    EngineSpec {
        name: "wasp",
        executable: "wasp",
        generates: "TypeScript full-stack",
        languages: &["typescript", "ts", "javascript", "js", "node"],
        capabilities: &[Capability::Backend, Capability::Frontend, Capability::Template],
        install_argv: None,
        install_hint: "curl -sSL https://get.wasp.sh/installer.sh | sh",
        regenerate_with_blueprint: "wasp compile",
        regenerate_default: "wasp compile",
        all_output_generated: false,
        required_args: &["name"],
        recipes: &[],
    },
    EngineSpec {
        name: "copier",
        executable: "copier",
        generates: "any Jinja template",
        languages: &[],
        capabilities: &[Capability::Template],
        install_argv: Some(&["uv", "tool", "install", "copier==9.17.0"]),
        install_hint: "uv tool install copier==9.17.0",
        regenerate_with_blueprint: "copier update --defaults --trust",
        regenerate_default: "copier update --defaults --trust",
        all_output_generated: false,
        required_args: &["name", "blueprint"],
        recipes: &[],
    },
    EngineSpec {
        name: "openapi",
        executable: "openapi-generator-cli",
        generates: "code from an OpenAPI spec",
        languages: &[],
        capabilities: &[Capability::SpecDriven],
        install_argv: Some(&["npm", "install", "-g", "@openapitools/openapi-generator-cli"]),
        install_hint: "npm install -g @openapitools/openapi-generator-cli (needs a JDK)",
        regenerate_with_blueprint: "openapi-generator-cli generate -i spec/{blueprint} -g {generator} -o .",
        regenerate_default: "openapi-generator-cli generate -i <spec> -g {generator} -o .",
        // Everything but the ignore file is the spec's.
        all_output_generated: true,
        required_args: &["name", "blueprint", "generator"],
        recipes: &[
            (
                "Python: spec-first",
                "vord kickoff --engine openapi --generator python-fastapi --blueprint api.yaml --name api",
            ),
            (
                "Python + Wasp: spec-first full-stack",
                "vord kickoff --engine openapi --generator python-fastapi --blueprint api.yaml --name app --frontend wasp",
            ),
        ],
    },
    EngineSpec {
        name: "typespec",
        executable: "npx",
        generates: "an OpenAPI contract from a TypeSpec API",
        languages: &[],
        capabilities: &[Capability::SpecDriven],
        install_argv: None,
        install_hint: "install Node.js 20+ (npx); the compiler is installed into the project by npm",
        regenerate_with_blueprint: "npm install && npx tsp compile main.tsp --emit @typespec/openapi3 --output-dir tsp-output",
        regenerate_default: "npm install && npx tsp compile main.tsp --emit @typespec/openapi3 --output-dir tsp-output",
        all_output_generated: false,
        required_args: &["name"],
        recipes: &[(
            "Contract first: TypeSpec -> OpenAPI",
            "vord kickoff --engine typespec --name api --entity todo:title=string,done=bool",
        )],
    },
    EngineSpec {
        name: "projen",
        executable: "npx",
        generates: "project configuration and CI workflows",
        languages: &[],
        capabilities: &[Capability::Template],
        install_argv: None,
        install_hint: "install Node.js 20+ (npx); projen is fetched by npx",
        regenerate_with_blueprint: "npx projen",
        regenerate_default: "npx projen",
        all_output_generated: false,
        required_args: &["name"],
        recipes: &[("Typed TypeScript project with CI", "vord kickoff --engine projen --name lib --generator typescript")],
    },
    EngineSpec {
        name: "zenstack",
        executable: "npx",
        generates: "typed data layer (TypeScript) from a data model",
        languages: &[],
        capabilities: &[Capability::SpecDriven, Capability::Backend],
        install_argv: None,
        install_hint: "install Node.js 20+ (npx); ZenStack is installed into the project by npm",
        regenerate_with_blueprint: "npm install && npx zen generate",
        regenerate_default: "npm install && npx zen generate",
        all_output_generated: false,
        required_args: &["name"],
        recipes: &[("Data layer from the app description", "vord kickoff --engine zenstack --name data --entity todo:title=string,done=bool")],
    },
];

/// Engine names, in registry order.
pub fn engine_names() -> Vec<&'static str> {
    ENGINES.iter().map(|spec| spec.name).collect()
}

/// `kthulu = Go, ferrum = Rust + React, ...` for error messages and schemas.
pub fn engine_languages_text() -> String {
    ENGINES
        .iter()
        .map(|spec| format!("{} = {}", spec.name, spec.generates))
        .collect::<Vec<_>>()
        .join(", ")
}

/// The engine that generates a backend in `language`.
pub fn engine_for_language(language: &str) -> Option<&'static EngineSpec> {
    let language = language.to_ascii_lowercase();
    ENGINES
        .iter()
        .find(|spec| spec.has(Capability::Backend) && spec.languages.contains(&language.as_str()))
}

/// `vord kickoff --list-engines`.
pub fn render_engines_text() -> String {
    let mut out = String::new();
    for spec in ENGINES {
        let caps: Vec<String> = spec
            .capabilities
            .iter()
            .map(|c| serde_json::to_value(c).ok().and_then(|v| v.as_str().map(str::to_string)).unwrap_or_default())
            .collect();
        out.push_str(&format!(
            "{}\n  generates:    {}\n  executable:   {}\n  capabilities: {}\n  install:      {}\n  regenerate:   {}\n  all output generated: {}\n  requires:     {}\n",
            spec.name,
            spec.generates,
            spec.executable,
            caps.join(", "),
            spec.install_hint,
            spec.regenerate_with_blueprint,
            if spec.all_output_generated { "yes" } else { "no" },
            spec.required_args.join(", "),
        ));
        for (title, command) in spec.recipes {
            out.push_str(&format!("  recipe:       {title}: {command}\n"));
        }
    }
    out
}

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
    /// TypeSpec: an API described in `main.tsp`, compiled to OpenAPI.
    TypeSpec,
    /// Projen: project configuration (package.json, tsconfig, CI workflows)
    /// generated from `.projenrc.ts`.
    Projen,
    /// ZenStack: typed data layer generated from `zenstack/schema.zmodel`.
    ZenStack,
}

impl Engine {
    pub fn parse(raw: &str) -> anyhow::Result<Self> {
        let lower = raw.to_ascii_lowercase();
        ENGINES
            .iter()
            .position(|spec| spec.name == lower)
            .map(|index| [Self::Kthulu, Self::Ferrum, Self::Wasp, Self::Copier, Self::OpenApi, Self::TypeSpec, Self::Projen, Self::ZenStack][index])
            .ok_or_else(|| {
                anyhow::anyhow!("unknown engine {lower:?}. Supported engines: {}", engine_names().join(", "))
            })
    }

    /// This engine's registry entry (variant order matches [`ENGINES`]).
    pub fn spec(self) -> &'static EngineSpec {
        &ENGINES[self as usize]
    }

    fn name(self) -> &'static str {
        self.spec().name
    }

    /// The executable the engine is run through.
    fn executable(self) -> &'static str {
        self.spec().executable
    }

    /// A pinned, non-interactive install, when one exists. Wasp's installer
    /// is a piped shell script, which vord does not run on its own.
    pub fn install_argv(self) -> Option<Vec<&'static str>> {
        self.spec().install_argv.map(<[&str]>::to_vec)
    }

    fn install_hint(self) -> &'static str {
        self.spec().install_hint
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
    /// Ferrum's template directory (`FERRUM_TEMPLATES`): `ferrum init` leaves
    /// the project's own `templates/` empty, so `compile` needs this.
    pub templates: Option<PathBuf>,
    /// Copier-only answers and template version.
    pub copier: CopierOptions,
    /// ferrum: backend only (`ferrum init --api-only`), because a Wasp
    /// frontend replaces its React one.
    pub api_only: bool,
}

/// Options only the copier engine takes.
#[derive(Debug, Default, Clone)]
pub struct CopierOptions {
    /// `key=value` answers, passed as `copier copy --data key=value`.
    pub data: Vec<String>,
    /// Template tag, branch or commit (`--vcs-ref`); copier defaults to the latest tag.
    pub vcs_ref: Option<String>,
}

impl CopierOptions {
    fn is_empty(&self) -> bool {
        self.data.is_empty() && self.vcs_ref.is_none()
    }

    /// Every `--data` entry must be `key=value` with an identifier as key.
    pub fn validate(&self) -> anyhow::Result<()> {
        for entry in &self.data {
            let key = entry
                .split_once('=')
                .map(|(k, _)| k)
                .ok_or_else(|| anyhow::anyhow!("--data expects key=value, got {entry:?}"))?;
            let mut chars = key.chars();
            let valid = chars.next().is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
                && chars.all(|c| c.is_ascii_alphanumeric() || c == '_');
            if !valid {
                anyhow::bail!("--data key {key:?} is not a valid copier question name");
            }
        }
        if self.vcs_ref.as_deref().is_some_and(|r| r.trim().is_empty() || r.starts_with('-')) {
            anyhow::bail!("--vcs-ref needs a tag, branch or commit");
        }
        Ok(())
    }
}

/// `FERRUM_TEMPLATES`, when set and non-empty.
pub fn ferrum_templates_from_env() -> Option<PathBuf> {
    std::env::var_os("FERRUM_TEMPLATES").filter(|v| !v.is_empty()).map(PathBuf::from)
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
        if self.engine != Engine::Copier && !self.copier.is_empty() {
            anyhow::bail!("--data and --vcs-ref only apply to --engine copier");
        }
        self.copier.validate()?;
        if self.engine == Engine::Ferrum && self.blueprint.is_some() {
            // Without it, the project's own templates/ is used; a ferrum that
            // leaves it empty is caught right before `compile` runs.
            if let Some(dir) = self.templates.as_ref().filter(|dir| !dir.is_dir()) {
                anyhow::bail!("FERRUM_TEMPLATES points at {}, which is not a directory", dir.display());
            }
        }
        match self.engine {
            Engine::Copier if self.blueprint.is_none() => {
                anyhow::bail!("engine copier needs --blueprint <template path or git URL>")
            }
            Engine::TypeSpec if self.blueprint.is_none() => {
                anyhow::bail!("engine typespec needs --blueprint <main.tsp> or --entity/--app to derive one")
            }
            Engine::ZenStack if self.blueprint.is_none() => {
                anyhow::bail!("engine zenstack needs --blueprint <schema.zmodel> or --entity/--app to derive one")
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
        lines.extend(self.preflight());
        lines
    }

    /// What would stop a real run: the engine is not on PATH. `--install`
    /// only helps for engines with a pinned installer; Wasp's is a piped
    /// shell script that vord never runs.
    pub fn preflight(&self) -> Vec<String> {
        let program = self.program();
        if self.program.is_some() || on_path(&program) {
            return Vec::new();
        }
        let hint = self.engine.install_hint();
        let line = match (self.install, self.engine.install_argv().is_some()) {
            (true, true) => format!(
                "preflight: {program} is not on PATH; --install will run `{}`",
                self.engine.install_argv().unwrap_or_default().join(" ")
            ),
            (true, false) => format!(
                "preflight: {program} is not on PATH and vord cannot install it (--install has no effect for {}); install it yourself: {hint}",
                self.engine.name()
            ),
            (false, _) => format!(
                "preflight: {program} is not on PATH; a real run would fail. Install it ({hint}) or pass --install where supported"
            ),
        };
        vec![line]
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
                // No `--skip-postgen`: released kthulu rejects it as an unknown
                // flag, so the engine's own post-generation runs.
                let mut args = vec![
                    "create".to_string(),
                    self.name.clone(),
                    "--output".to_string(),
                    self.project_dir().display().to_string(),
                ];
                if let Some(plan) = self.blueprint_arg() {
                    args.extend(["--from-plan".to_string(), plan]);
                }
                steps.push(Step { program, args, cwd: self.parent.clone() });
            }
            Engine::Ferrum => {
                steps.push(Step {
                    program: program.clone(),
                    args: {
                        let mut args = vec!["init".to_string(), self.name.clone()];
                        if self.api_only {
                            args.push("--api-only".to_string());
                        }
                        args
                    },
                    cwd: self.parent.clone(),
                });
                if let Some(graph) = self.blueprint_arg() {
                    let mut args = vec!["compile".to_string(), graph, "--output".to_string(), ".".to_string()];
                    args.extend(self.templates_args());
                    steps.push(Step { program, args, cwd: self.project_dir() });
                }
            }
            Engine::Wasp => {
                steps.push(Step {
                    program,
                    args: vec!["new".to_string(), self.name.clone(), "-t".to_string(), "minimal".to_string()],
                    cwd: self.parent.clone(),
                });
            }
            Engine::Copier => {
                let mut args = vec!["copy".to_string(), "--defaults".to_string(), "--trust".to_string()];
                for entry in &self.copier.data {
                    args.extend(["--data".to_string(), entry.clone()]);
                }
                if let Some(vcs_ref) = &self.copier.vcs_ref {
                    args.extend(["--vcs-ref".to_string(), vcs_ref.clone()]);
                }
                args.extend(self.blueprint_arg());
                args.push(self.project_dir().display().to_string());
                steps.push(Step { program, args, cwd: self.parent.clone() });
            }
            Engine::TypeSpec => {
                let dir = self.project_dir();
                let npm = if self.program.is_some() { program.clone() } else { "npm".to_string() };
                steps.push(Step { program: npm, args: vec!["install".to_string()], cwd: dir.clone() });
                let args = ["tsp", "compile", "main.tsp", "--emit", "@typespec/openapi3", "--output-dir", "tsp-output"];
                steps.push(Step { program, args: args.iter().map(|a| a.to_string()).collect(), cwd: dir });
            }
            Engine::ZenStack => {
                let dir = self.project_dir();
                let npm = if self.program.is_some() { program.clone() } else { "npm".to_string() };
                steps.push(Step { program: npm, args: vec!["install".to_string()], cwd: dir.clone() });
                steps.push(Step { program, args: vec!["zen".to_string(), "generate".to_string()], cwd: dir });
            }
            Engine::Projen => {
                let kind = self.generator.clone().unwrap_or_else(|| "typescript".to_string());
                let args = ["--yes", PROJEN_PACKAGE, "new", &kind, "--no-git", "--no-post", "--name", &self.name];
                steps.push(Step { program, args: args.iter().map(|a| a.to_string()).collect(), cwd: self.project_dir() });
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

    fn templates_args(&self) -> Vec<String> {
        match (&self.engine, &self.templates) {
            (Engine::Ferrum, Some(dir)) => {
                let dir = std::fs::canonicalize(dir).unwrap_or_else(|_| dir.clone());
                vec!["--templates".to_string(), dir.display().to_string()]
            }
            _ => Vec::new(),
        }
    }

    /// Where the blueprint lives inside the project, when the engine needs it
    /// there to regenerate from the project root (ferrum: `gen/<file>`,
    /// openapi: `spec/<file>`).
    fn staged_blueprint(&self) -> Option<String> {
        let file = self.blueprint.as_ref()?.file_name()?.to_string_lossy().to_string();
        match self.engine {
            Engine::Ferrum => Some(format!("gen/{file}")),
            Engine::OpenApi => Some(format!("spec/{file}")),
            Engine::TypeSpec => Some("main.tsp".to_string()),
            Engine::ZenStack => Some("zenstack/schema.zmodel".to_string()),
            _ => None,
        }
    }

    /// The command recorded in the manifest as how to regenerate; runnable
    /// from the project root.
    pub fn regenerate_command(&self) -> String {
        let blueprint = self
            .blueprint
            .as_ref()
            .and_then(|p| p.file_name())
            .map(|f| f.to_string_lossy().to_string());
        let mut command = self.engine.spec().regenerate(&self.name, blueprint.as_deref(), self.generator.as_deref());
        if blueprint.is_some() {
            for arg in self.templates_args() {
                command.push(' ');
                command.push_str(&arg);
            }
        }
        command
    }
}

/// Paths a generator leaves for the developer to write, by generator name.
/// OpenAPI Generator writes these once and, when they are listed in
/// `.openapi-generator-ignore`, never touches them again. `python-fastapi`
/// emits `Base*Api` classes and an empty `impl` package that is scanned at
/// import time: the handlers are the developer's own modules in `impl/`.
fn user_owned_patterns(generator: &str) -> &'static [&'static str] {
    match generator {
        "python-fastapi" => &[
            "src/*/impl/**",
            "tests/**",
            // Project scaffolding a developer edits (dependencies, ignores, docs).
            "/README.md",
            "/.gitignore",
            "/requirements.txt",
            "/pyproject.toml",
            "/setup.cfg",
            "/Dockerfile",
            "/docker-compose.yaml",
        ],
        _ => &[],
    }
}

/// Add the generator's user-owned patterns to `.openapi-generator-ignore`
/// (after the first generation, so the stubs exist once) and return the
/// matcher over everything that file lists.
fn openapi_user_owned(project_dir: &Path, generator: &str) -> anyhow::Result<ignore::gitignore::Gitignore> {
    let file = project_dir.join(".openapi-generator-ignore");
    let mut content = std::fs::read_to_string(&file).unwrap_or_default();
    let present: BTreeSet<&str> = content.lines().map(str::trim).collect();
    let missing: Vec<&str> = user_owned_patterns(generator).iter().copied().filter(|p| !present.contains(p)).collect();
    if !missing.is_empty() {
        if !content.is_empty() && !content.ends_with('\n') {
            content.push('\n');
        }
        content.push_str("\n# Written by you, not by the generator (added by vord kickoff):\n");
        for pattern in missing {
            content.push_str(pattern);
            content.push('\n');
        }
        std::fs::write(&file, content)?;
    }
    let mut builder = ignore::gitignore::GitignoreBuilder::new(project_dir);
    if file.is_file() {
        if let Some(err) = builder.add(&file) {
            return Err(err.into());
        }
    }
    Ok(builder.build()?)
}

/// `Command::status`, retried while the kernel answers ETXTBSY ("text file
/// busy"). A program that was written an instant ago (an installer, a
/// freshly built engine) can still be held open for writing by a process
/// forked in between; the condition clears within milliseconds.
fn status_retrying(command: &mut Command) -> std::io::Result<std::process::ExitStatus> {
    let mut attempt = 0;
    loop {
        match command.status() {
            Err(e) if e.raw_os_error() == Some(26) && attempt < 8 => {
                attempt += 1;
                std::thread::sleep(std::time::Duration::from_millis(25 * attempt));
            }
            other => return other,
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
        || head.contains("Generated by projen")
        || head.contains("DO NOT MODIFY THIS FILE")
}

/// What `run` did, for the caller to report.
#[derive(Debug)]
pub struct KickoffReport {
    pub project_dir: PathBuf,
    pub created: usize,
    pub generated: usize,
    /// Things the caller should tell the person: skipped steps, fallbacks.
    pub notes: Vec<String>,
}

/// Runs the engine, then layers vord's governance on top of its output. A
/// project directory this run created is removed again if the run fails, and
/// the error says so; a directory that already existed is never touched.
pub fn run(kickoff: &EngineKickoff) -> anyhow::Result<KickoffReport> {
    let mut report = run_engine(kickoff)?;
    finish_project(&report.project_dir, &mut report.notes)?;
    Ok(report)
}

/// What a freshly generated project needs so the agent can start at once:
/// the analyzer baseline `vord_done` compares against, an `.mcp.json` that
/// offers vord's tools to Claude Code, and a warning when the hook command
/// is not on PATH (without it the write gate silently does nothing).
fn finish_project(root: &Path, notes: &mut Vec<String>) -> anyhow::Result<()> {
    let baseline = root.join(vord_cli::agent::DONE_BASELINE_FILE);
    let findings = std::thread::scope(|scope| {
        scope
            .spawn(|| {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()?
                    .block_on(vord_cli::agent::write_baseline(root, ".", &baseline))
            })
            .join()
            .unwrap_or_else(|_| Err(anyhow::anyhow!("the baseline scan panicked")))
    })?;
    notes.push(format!(
        "{} written ({findings} existing finding(s)): vord_done reports only what the agent adds after this point",
        vord_cli::agent::DONE_BASELINE_FILE
    ));
    let mcp = root.join(".mcp.json");
    if !mcp.exists() {
        std::fs::write(
            &mcp,
            "{\n  \"mcpServers\": {\n    \"vord\": { \"command\": \"vord\", \"args\": [\"mcp\"] }\n  }\n}\n",
        )?;
        notes.push(".mcp.json written: Claude Code offers vord's tools (vord_scan, vord_holes, vord_done) in this project".to_string());
    }
    if !on_path("vord") {
        notes.push(
            "`vord` is not on PATH: the write gate (`vord hook claude-code`) and `vord mcp` cannot start until it is, so nothing is protected yet".to_string(),
        );
    }
    Ok(())
}

fn run_engine(kickoff: &EngineKickoff) -> anyhow::Result<KickoffReport> {
    kickoff.validate()?;
    let project_dir = kickoff.project_dir();
    let existed = project_dir.exists();
    run_inner(kickoff).map_err(|err| {
        if !existed && project_dir.exists() {
            match std::fs::remove_dir_all(&project_dir) {
                Ok(()) => err.context(format!("removed the partial {}", project_dir.display())),
                Err(e) => err.context(format!("{} was left partially generated (could not remove it: {e})", project_dir.display())),
            }
        } else {
            err
        }
    })
}

fn run_inner(kickoff: &EngineKickoff) -> anyhow::Result<KickoffReport> {
    let project_dir = kickoff.project_dir();
    let before = list_files(&project_dir);
    let pin_existed = kickoff.parent.join("openapitools.json").exists();
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

    // Node-based engines run inside the project, so it must exist with its
    // package.json and blueprint before the first step.
    if let Some(manifest) = node_manifest(kickoff.engine, &kickoff.name) {
        std::fs::create_dir_all(&project_dir)?;
        std::fs::write(project_dir.join("package.json"), manifest)?;
        if let (Some(staged), Some(blueprint)) = (kickoff.staged_blueprint(), kickoff.blueprint.as_ref()) {
            let target = project_dir.join(&staged);
            if let Some(dir) = target.parent() {
                std::fs::create_dir_all(dir)?;
            }
            std::fs::copy(blueprint, &target)?;
        }
    } else if kickoff.engine == Engine::Projen {
        std::fs::create_dir_all(&project_dir)?;
    }
    for step in kickoff.steps() {
        if kickoff.engine == Engine::Ferrum
            && step.args.first().map(String::as_str) == Some("compile")
            && !step.args.iter().any(|a| a == "--templates")
            && std::fs::read_dir(step.cwd.join("templates")).map_or(true, |mut d| d.next().is_none())
        {
            anyhow::bail!(
                "this ferrum leaves the project's templates/ empty, so `ferrum compile` has nothing to render with: use a ferrum that copies them on init (pmaojo/ferrum#324) or set FERRUM_TEMPLATES=<ferrum checkout>/templates"
            );
        }
        let status = status_retrying(Command::new(&step.program).args(&step.args).current_dir(&step.cwd))
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
    // `ferrum init` seeds its `users` example graph; once the project has its
    // own, leaving it behind makes the scaffold look like a users app.
    if kickoff.engine == Engine::Ferrum && kickoff.staged_blueprint().is_some_and(|staged| staged != "gen/example.yaml") {
        let _ = std::fs::remove_file(project_dir.join("gen/example.yaml"));
    }
    if !project_dir.is_dir() {
        anyhow::bail!(
            "{} finished but {} does not exist",
            kickoff.engine.name(),
            project_dir.display()
        );
    }

    let mut created: Vec<String> = list_files(&project_dir).difference(&before).cloned().collect();
    let mut manifest = Manifest::load(&project_dir);
    let source = kickoff.staged_blueprint().or_else(|| {
        kickoff
            .blueprint
            .as_ref()
            .and_then(|p| p.file_name())
            .map(|f| f.to_string_lossy().to_string())
    });
    let regenerate = kickoff.regenerate_command();
    // Files the project owns (listed in .openapi-generator-ignore) are never
    // locked: the developer writes them and the generator leaves them alone.
    let user_owned = match (kickoff.engine, kickoff.generator.as_deref()) {
        (Engine::OpenApi, Some(generator)) => Some(openapi_user_owned(&project_dir, generator)?),
        _ => None,
    };
    for relative in &created {
        if user_owned
            .as_ref()
            .is_some_and(|ignored| ignored.matched_path_or_any_parents(relative, false).is_ignore())
        {
            continue;
        }
        let Ok(content) = std::fs::read_to_string(project_dir.join(relative)) else {
            continue; // binary output is never hand-edited through a text tool
        };
        // OpenAPI Generator output is wholly the spec's; its ignore file lists
        // what the project owns instead.
        let wholly_generated = kickoff.engine.spec().all_output_generated && relative != ".openapi-generator-ignore";
        let engine_output = kickoff.engine == Engine::TypeSpec && relative.starts_with("tsp-output/");
        if wholly_generated || engine_output || is_marked_generated(&content) {
            // templ output is regenerated by templ, not by the scaffolder.
            let regenerate = if content.lines().take(3).any(|l| l.contains("Code generated by templ")) {
                "templ generate".to_string()
            } else {
                regenerate.clone()
            };
            manifest.files.insert(
                relative.clone(),
                GeneratedFile {
                    engine: kickoff.engine.name().to_string(),
                    source: source.clone(),
                    regenerate: Some(regenerate),
                },
            );
        }
    }
    manifest.save(&project_dir)?;

    // Regeneration runs from the project root, so the blueprint and the
    // engine wrapper's version pin live there too.
    if let (Some(staged), Some(blueprint)) = (kickoff.staged_blueprint(), kickoff.blueprint.as_ref()) {
        let target = project_dir.join(&staged);
        let same = std::fs::canonicalize(blueprint).ok() == std::fs::canonicalize(&target).ok();
        if !same {
            if let Some(dir) = target.parent() {
                std::fs::create_dir_all(dir)?;
            }
            std::fs::copy(blueprint, &target)?;
            created.push(staged);
        }
    }
    if kickoff.engine == Engine::OpenApi && !pin_existed {
        let pin = kickoff.parent.join("openapitools.json");
        if pin.is_file() {
            std::fs::rename(&pin, project_dir.join("openapitools.json")).ok();
        }
    }

    if node_manifest(kickoff.engine, &kickoff.name).is_some() {
        ensure_gitignored(&project_dir, "node_modules/")?;
    }
    crate::hook_install::install(&project_dir, crate::hook_install::DEFAULT_HOOK_COMMAND)?;
    if kickoff.engine == Engine::Wasp {
        protect_wasp_output(&project_dir, "")?;
    }
    crate::kickoff::write_gherkin_scaffold(&project_dir, "app", &format!("{} application", kickoff.name))?;
    ignore_session_state(&project_dir)?;

    let notes = manifest_ignored_note(&project_dir).into_iter().collect();
    Ok(KickoffReport {
        project_dir,
        created: created.len(),
        generated: manifest.files.len(),
        notes,
    })
}

/// The blueprint an engine gets for `app`: only ferrum has a graph vord can
/// derive (kthulu's `--from-plan` format is not verified against its CLI).
pub fn app_blueprint(app: &crate::app_spec::AppSpec, engine: Engine) -> anyhow::Result<PathBuf> {
    let (file, content) = match engine {
        Engine::Ferrum => (format!("{}.yaml", app.name), app.ferrum_graph()),
        Engine::TypeSpec => ("main.tsp".to_string(), app.typespec()),
        Engine::ZenStack => ("schema.zmodel".to_string(), app.zmodel()),
        _ => anyhow::bail!(
            "an app description (--app/--entity) derives blueprints for ferrum, typespec and zenstack; {} has none yet, pass --blueprint instead",
            engine.name()
        ),
    };
    let dir = std::env::temp_dir().join(format!("vord-app-{}-{}-{}", std::process::id(), app.name, engine.name()));
    std::fs::create_dir_all(&dir)?;
    let path = dir.join(file);
    std::fs::write(&path, content)?;
    Ok(path)
}

/// Keeps the description in the project (`app.json`) as the source the graph
/// and the contract are derived from.
pub fn record_app(app: &crate::app_spec::AppSpec, project_dir: &Path) -> anyhow::Result<()> {
    std::fs::write(
        project_dir.join("app.json"),
        serde_json::to_string_pretty(app)? + "\n",
    )?;
    Ok(())
}

/// Builds what the engine generated and, when it does not build, records a
/// generator defect and says so: an agent that meets broken generated code
/// must report it, not patch around it. `dir` is where the generated crate
/// or module lives (`backend` in a full-stack project). Engines without a
/// cheap build check (Wasp, copier, openapi) are skipped.
pub fn check_build(project_dir: &Path, engine: Engine, dir: Option<&str>, notes: &mut Vec<String>) {
    let argv: &[&str] = match engine {
        Engine::Ferrum => &["cargo", "check", "--quiet"],
        Engine::Kthulu => &["go", "build", "./..."],
        _ => {
            notes.push(format!("no build check for {}; nothing was verified", engine.name()));
            return;
        }
    };
    let cwd = match (engine, dir) {
        // ferrum's crate is `backend/` inside its project directory.
        (Engine::Ferrum, None) => project_dir.join("backend"),
        (Engine::Ferrum, Some(dir)) => project_dir.join(dir).join("backend"),
        (_, Some(dir)) => project_dir.join(dir),
        _ => project_dir.to_path_buf(),
    };
    run_build_check(project_dir, engine.name(), argv, &cwd, notes);
}

fn run_build_check(project_dir: &Path, engine: &str, argv: &[&str], cwd: &Path, notes: &mut Vec<String>) {
    if !available(argv[0]) {
        notes.push(format!("build check skipped: {} is not on PATH", argv[0]));
        return;
    }
    let output = match Command::new(argv[0]).args(&argv[1..]).current_dir(cwd).output() {
        Ok(output) => output,
        Err(e) => {
            notes.push(format!("build check could not run `{}`: {e}", argv.join(" ")));
            return;
        }
    };
    if output.status.success() {
        notes.push(format!("build check passed (`{}` in {})", argv.join(" "), cwd.display()));
        return;
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    let tail: Vec<&str> = stderr.lines().rev().take(12).collect::<Vec<_>>().into_iter().rev().collect();
    let reason = format!("`{}` fails on the generated code: {}", argv.join(" "), tail.join(" | "));
    match crate::generator_defects::report(project_dir, engine, &cwd.strip_prefix(project_dir).unwrap_or(cwd).display().to_string(), &reason) {
        Ok(defect) => notes.push(format!(
            "GENERATED CODE DOES NOT BUILD (defect #{} in {}): fix the blueprint or {}'s template and regenerate; do not edit the generated files. `vord agent done` stays not-done until `vord defects resolve {}`. Output tail: {}",
            defect.id,
            crate::generator_defects::DEFECTS_FILE,
            engine,
            defect.id,
            tail.join(" | ")
        )),
        Err(e) => notes.push(format!("generated code does not build and the defect could not be recorded: {e}")),
    }
}

const PROJEN_PACKAGE: &str = "projen@0.103.27";

/// What npm needs to run the node-based engines inside the project.
fn node_manifest(engine: Engine, name: &str) -> Option<String> {
    let deps = match engine {
        Engine::TypeSpec => r#""@typespec/compiler": "1.16.0", "@typespec/http": "1.16.0", "@typespec/openapi": "1.16.0", "@typespec/openapi3": "1.16.0""#,
        Engine::ZenStack => r#""@zenstackhq/cli": "3.9.7", "@zenstackhq/orm": "3.9.7", "kysely": "^0.28.0", "typescript": "^5""#,
        _ => return None,
    };
    Some(format!("{{\n  \"name\": \"{name}\",\n  \"private\": true,\n  \"type\": \"module\",\n  \"dependencies\": {{ {deps} }}\n}}\n"))
}

/// The command that rewrites a contract from `app.json`.
pub const CONTRACT_REGENERATE: &str =
    "vord kickoff --app app.json --emit-contract contract/openapi.yaml";

/// A backend engine and a Wasp frontend generated side by side, joined by one
/// OpenAPI contract: the backend serves it, the frontend's typed client is
/// generated from it, and neither side hand-writes the API layer.
pub struct FullstackKickoff {
    pub backend: Engine,
    pub name: String,
    /// The backend engine's blueprint.
    pub blueprint: Option<PathBuf>,
    /// OpenAPI Generator's generator name, when the backend engine is `openapi`.
    pub generator: Option<String>,
    pub parent: PathBuf,
    pub install: bool,
    /// Executable overrides by part (`backend`, `frontend`), for tests.
    pub programs: std::collections::BTreeMap<String, String>,
    /// The app to create, described as entities; ferrum's graph and the
    /// contract are derived from it.
    pub app: Option<crate::app_spec::AppSpec>,
}

impl FullstackKickoff {
    fn part(&self, engine: Engine, dir: &str, blueprint: Option<PathBuf>, root: &Path) -> EngineKickoff {
        EngineKickoff {
            engine,
            name: dir.to_string(),
            blueprint,
            parent: root.to_path_buf(),
            program: self.programs.get(dir).cloned(),
            generator: if engine == Engine::OpenApi { self.generator.clone() } else { None },
            install: self.install,
            templates: self
                .programs
                .get("templates")
                .map(PathBuf::from)
                .or_else(ferrum_templates_from_env),
            copier: Default::default(),
            api_only: engine == Engine::Ferrum,
        }
    }

    /// Every command that would run, for `--plan`.
    pub fn plan(&self) -> Vec<String> {
        let root = self.parent.join(&self.name);
        let mut lines = self.part(self.backend, "backend", self.blueprint.clone(), &root).plan();
        lines.extend(self.part(Engine::Wasp, "frontend", None, &root).plan());
        if self.backend == Engine::OpenApi {
            lines.push("copy your spec verbatim to contract/openapi.yaml".to_string());
        } else {
            lines.push("(if the backend produced an OpenAPI document) copy it to contract/openapi.yaml".to_string());
        }
        lines.push(format!("{}/frontend: npx -y {CLIENT_PACKAGE} ../contract/openapi.yaml -o src/api/schema.ts", root.display()));
        if !available("npx") {
            lines.push("preflight: npx is not on PATH; the typed client frontend/src/api/schema.ts would be skipped".to_string());
        }
        lines
    }
}

/// The command that regenerates the frontend's typed API client.
pub const CLIENT_REGENERATE: &str =
    "npx -y openapi-typescript@7.13.0 ../contract/openapi.yaml -o src/api/schema.ts";

/// The pinned generator, so the client is the same on every machine.
const CLIENT_PACKAGE: &str = "openapi-typescript@7.13.0";

/// File names a backend engine may serve its OpenAPI document under.
const SPEC_NAMES: &[&str] = &[
    "openapi.yaml", "openapi.yml", "openapi.json", "swagger.yaml", "swagger.yml", "swagger.json",
];

/// The OpenAPI document the backend produced: the shallowest file with a
/// well-known name that actually declares itself as OpenAPI/Swagger.
fn find_backend_spec(backend: &Path) -> Option<PathBuf> {
    let mut found: Vec<String> = list_files(backend)
        .into_iter()
        .filter(|f| SPEC_NAMES.contains(&f.rsplit('/').next().unwrap_or(f)))
        .filter(|f| {
            std::fs::read_to_string(backend.join(f))
                .map(|c| c.contains("openapi") || c.contains("swagger"))
                .unwrap_or(false)
        })
        .collect();
    found.sort_by_key(|f| (f.matches('/').count(), f.clone()));
    found.into_iter().next().map(|f| backend.join(f))
}

/// Is `program` runnable: a path that is a file, or a name on PATH?
fn available(program: &str) -> bool {
    if program.contains('/') || program.contains(std::path::MAIN_SEPARATOR) {
        Path::new(program).is_file()
    } else {
        on_path(program)
    }
}

/// Backend into `<name>/backend`, Wasp into `<name>/frontend`, one governed
/// workspace at `<name>`. Only the backend languages a Wasp frontend can sit
/// on are accepted.
pub fn run_fullstack(kickoff: &FullstackKickoff) -> anyhow::Result<KickoffReport> {
    if kickoff.backend == Engine::Wasp {
        anyhow::bail!("--frontend wasp already is a full-stack engine; pick a backend engine: ferrum (Rust), kthulu (Go) or openapi (any server generator, e.g. python-fastapi)");
    }
    let root = kickoff.parent.join(&kickoff.name);
    // Check both engines before generating anything: a missing frontend
    // engine must not strand a finished backend.
    for (engine, dir) in [(kickoff.backend, "backend"), (Engine::Wasp, "frontend")] {
        let program = kickoff.programs.get(dir).cloned().unwrap_or_else(|| engine.executable().to_string());
        if on_path(&program) || kickoff.programs.contains_key(dir) {
            continue;
        }
        if !kickoff.install || engine.install_argv().is_none() {
            anyhow::bail!(
                "{program} is not on PATH; nothing was generated. Install it{}: {}",
                if kickoff.install { " yourself (vord does not run its installer)" } else { "" },
                engine.install_hint()
            );
        }
    }
    let existed = root.exists();
    std::fs::create_dir_all(&root)?;
    run_fullstack_inner(kickoff, &root).map_err(|err| {
        if existed {
            err.context(format!("{} may be partially generated", root.display()))
        } else {
            match std::fs::remove_dir_all(&root) {
                Ok(()) => err.context(format!("removed the partial {}", root.display())),
                Err(e) => err.context(format!("{} was left partially generated (could not remove it: {e})", root.display())),
            }
        }
    })
}

fn run_fullstack_inner(kickoff: &FullstackKickoff, root: &Path) -> anyhow::Result<KickoffReport> {
    let mut created = 0;
    let blueprint = match (&kickoff.blueprint, &kickoff.app) {
        (None, Some(app)) => Some(app_blueprint(app, kickoff.backend)?),
        (blueprint, _) => blueprint.clone(),
    };
    for (engine, dir, blueprint) in [
        (kickoff.backend, "backend", blueprint),
        (Engine::Wasp, "frontend", None),
    ] {
        let part = kickoff.part(engine, dir, blueprint, root);
        created += run_engine(&part)?.created;
    }

    // One manifest and one hook at the workspace root, where the agent works.
    let mut manifest = Manifest::load(root);
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
        // The Gherkin scaffold lives once, at the workspace root.
        std::fs::remove_file(part.join("features/app.feature")).ok();
        std::fs::remove_dir(part.join("features")).ok(); // only if now empty
    }
    crate::kickoff::write_gherkin_scaffold(root, "app", &format!("{} application", kickoff.name))?;
    std::fs::create_dir_all(root.join("contract"))?;
    let contract = root.join("contract/openapi.yaml");
    let mut notes = Vec::new();
    if !contract.exists() {
        if let (Engine::OpenApi, Some(spec)) = (kickoff.backend, kickoff.blueprint.as_ref()) {
            // Spec-first: the user's spec is the contract, verbatim.
            std::fs::copy(spec, &contract)?;
            notes.push("contract/openapi.yaml is your spec, copied verbatim (edit it, then regenerate backend and client)".to_string());
        } else if let Some(spec) = find_backend_spec(&root.join("backend")) {
            std::fs::copy(&spec, &contract)?; // JSON is valid YAML
            notes.push(format!(
                "contract/openapi.yaml copied from the backend's {}",
                spec.strip_prefix(root.join("backend")).unwrap_or(&spec).display()
            ));
        } else if let Some(app) = &kickoff.app {
            std::fs::write(&contract, app.openapi())?;
            notes.push(
                "contract/openapi.yaml is derived from app.json: it is the API the app should expose. ferrum's generated routes follow the same CRUD shape, but nothing checks the two against each other yet"
                    .to_string(),
            );
        } else {
            std::fs::write(
                &contract,
                format!("openapi: 3.0.3\ninfo:\n  title: {}\n  version: 0.1.0\npaths: {{}}\n", kickoff.name),
            )?;
            notes.push(
                "the backend produced no OpenAPI document; contract/openapi.yaml is an empty stub to fill in".to_string(),
            );
        }
        created += 1;
    }

    // The frontend's typed client, generated from the contract.
    let npx = kickoff.programs.get("client").cloned().unwrap_or_else(|| "npx".to_string());
    if available(&npx) {
        let frontend = root.join("frontend");
        let schema = frontend.join("src/api/schema.ts");
        std::fs::create_dir_all(frontend.join("src/api"))?;
        let status = status_retrying(
            Command::new(&npx)
                .args(["-y", CLIENT_PACKAGE, "../contract/openapi.yaml", "-o", "src/api/schema.ts"])
                .current_dir(&frontend),
        )
        .map_err(|e| anyhow::anyhow!("could not run {npx}: {e}"))?;
        if !status.success() {
            anyhow::bail!("`{npx} -y {CLIENT_PACKAGE}` failed ({status}) while generating frontend/src/api/schema.ts");
        }
        let body = std::fs::read_to_string(&schema)
            .map_err(|e| anyhow::anyhow!("{CLIENT_PACKAGE} wrote no frontend/src/api/schema.ts: {e}"))?;
        std::fs::write(
            &schema,
            format!("// Code generated by {CLIENT_PACKAGE} from contract/openapi.yaml. DO NOT EDIT.\n{body}"),
        )?;
        manifest.files.insert(
            "frontend/src/api/schema.ts".to_string(),
            GeneratedFile {
                engine: "openapi-typescript".to_string(),
                source: Some("contract/openapi.yaml".to_string()),
                regenerate: Some(format!("cd frontend && {CLIENT_REGENERATE}")),
            },
        );
        created += 1;
    } else {
        notes.push(format!(
            "{npx} is not available, so frontend/src/api/schema.ts was not generated; install Node.js, then run: cd frontend && {CLIENT_REGENERATE}"
        ));
    }
    if let Some(app) = &kickoff.app {
        record_app(app, root)?;
        manifest.files.insert(
            "contract/openapi.yaml".to_string(),
            GeneratedFile {
                engine: "vord".to_string(),
                source: Some("app.json".to_string()),
                regenerate: Some(CONTRACT_REGENERATE.to_string()),
            },
        );
    }
    if !root.join("redocly.yaml").exists() {
        std::fs::write(root.join("redocly.yaml"), crate::verify::REDOCLY_CONFIG)?;
    }
    manifest.save(root)?;
    crate::hook_install::install(root, crate::hook_install::DEFAULT_HOOK_COMMAND)?;
    protect_wasp_output(root, "frontend/")?;
    ignore_session_state(root)?;
    std::fs::write(
        root.join("contract/README.md"),
        format!(
            "The API contract shared by `backend/` and `frontend/`.\n\n`openapi.yaml` is your own spec when the backend is `--engine openapi` (spec-first), else the backend's own OpenAPI document when the backend engine produced one, otherwise an empty stub to fill in. `frontend/src/api/schema.ts` is generated from it (recorded in `.vord/generated.json`, so edits are blocked): change `openapi.yaml`, then regenerate the typed client with:\n\n    cd frontend && {CLIENT_REGENERATE}\n\nRegenerating drops the `Code generated ... DO NOT EDIT` header line; the manifest keeps the file protected regardless.\n"
        ),
    )?;
    notes.extend(manifest_ignored_note(root));
    finish_project(root, &mut notes)?;
    Ok(KickoffReport { project_dir: root.to_path_buf(), created, generated: manifest.files.len(), notes })
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

/// A warning when git ignores `.vord/generated.json` (usually a broad
/// `.vord/` line in the workspace's own `.gitignore`): the manifest is what
/// makes the write gate work, so it has to be committed. vord itself only
/// ever ignores `.vord/sessions/`.
fn manifest_ignored_note(project_dir: &Path) -> Option<String> {
    let ignored = Command::new("git")
        .args(["check-ignore", "-q", vord_cli::generated::MANIFEST_FILE])
        .current_dir(project_dir)
        .status()
        .ok()?
        .success();
    ignored.then(|| {
        format!(
            "git ignores {}: without it a fresh clone has no write gate on generated code. Replace a broad `.vord/` ignore with `.vord/sessions/`.",
            vord_cli::generated::MANIFEST_FILE
        )
    })
}

/// Per-session analyzer baselines (dsh-vord) are local state, not source.
fn ignore_session_state(project_dir: &Path) -> anyhow::Result<()> {
    ensure_gitignored(project_dir, ".vord/sessions/")
}

/// Adds `line` to `.gitignore` unless it is there or the file is projen's
/// (projen rewrites it from `.projenrc.ts`, dropping anything added by hand).
fn ensure_gitignored(project_dir: &Path, line: &str) -> anyhow::Result<()> {
    let gitignore = project_dir.join(".gitignore");
    let mut content = std::fs::read_to_string(&gitignore).unwrap_or_default();
    if content.lines().any(|l| l.trim() == line) || content.contains("Generated by projen") {
        return Ok(());
    }
    if !content.is_empty() && !content.ends_with('\n') {
        content.push('\n');
    }
    content.push_str(line);
    content.push('\n');
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
            templates: None,
            copier: Default::default(),
            api_only: false,
        }
    }

    #[test]
    fn kthulu_creates_from_the_plan_with_only_flags_the_released_cli_has() {
        let steps = kickoff(Engine::Kthulu, Some("/plans/kthulu-plan.yaml")).steps();
        assert_eq!(steps.len(), 1);
        assert_eq!(steps[0].program, "kthulu");
        assert_eq!(
            steps[0].args,
            ["create", "shop", "--output", "/work/shop", "--from-plan", "/plans/kthulu-plan.yaml"]
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
    fn ferrum_templates_reach_compile_and_the_regenerate_command() {
        let mut k = kickoff(Engine::Ferrum, Some("/plans/users.yaml"));
        k.templates = Some(PathBuf::from("/nonexistent/ferrum/templates"));
        assert_eq!(
            k.steps()[1].args,
            ["compile", "/plans/users.yaml", "--output", ".", "--templates", "/nonexistent/ferrum/templates"]
        );
        // Runnable from the project root: the graph is staged under gen/.
        assert_eq!(
            k.regenerate_command(),
            "ferrum compile gen/users.yaml --output . --templates /nonexistent/ferrum/templates"
        );
        assert_eq!(k.staged_blueprint().as_deref(), Some("gen/users.yaml"));
    }

    #[test]
    fn install_commands_name_the_ferrum_cli_package() {
        assert_eq!(Engine::Ferrum.install_argv().unwrap().last(), Some(&"ferrum-cli"));
        assert!(Engine::Ferrum.spec().install_hint.ends_with("ferrum-cli"));
    }

    #[test]
    fn wasp_runs_wasp_new() {
        let steps = kickoff(Engine::Wasp, None).steps();
        assert_eq!(steps[0].args, ["new", "shop", "-t", "minimal"]);
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
            templates: None,
            copier: Default::default(),
            api_only: false,
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
        // The agent can finish at once: baseline for vord_done and the MCP entry.
        assert!(dir.join(vord_cli::agent::DONE_BASELINE_FILE).is_file());
        let mcp = std::fs::read_to_string(dir.join(".mcp.json")).unwrap();
        assert!(mcp.contains("\"command\": \"vord\"") && mcp.contains("\"mcp\""));
        assert!(report.notes.iter().any(|n| n.contains("agent-baseline.json")));
        std::fs::remove_dir_all(&parent).ok();
    }

    #[test]
    fn plan_flags_a_missing_engine_and_says_install_cannot_help_for_wasp() {
        let mut k = kickoff(Engine::Wasp, None);
        k.program = None;
        k.name = "x".into();
        // Force a name that cannot be on PATH.
        let missing = Engine::Wasp.executable() == "wasp" && !on_path("wasp");
        if missing {
            let plain = k.plan().join("\n");
            assert!(plain.contains("preflight: wasp is not on PATH"), "{plain}");
            k.install = true;
            assert!(k.plan().join("\n").contains("vord cannot install it"));
        }
        k.program = Some("/bin/sh".into());
        assert!(k.preflight().is_empty(), "an explicit program is trusted");
    }

    #[test]
    fn copier_data_and_vcs_ref_become_copy_flags_and_are_validated() {
        let mut k = kickoff(Engine::Copier, Some("gh:org/tpl"));
        k.copier = CopierOptions {
            data: vec!["project_name=My API".into(), "debug=true".into(), "note=a=b".into()],
            vcs_ref: Some("0.9.0".into()),
        };
        k.validate().unwrap();
        assert_eq!(
            k.steps()[0].args[..11],
            ["copy", "--defaults", "--trust", "--data", "project_name=My API", "--data", "debug=true", "--data", "note=a=b", "--vcs-ref", "0.9.0"]
        );
        for bad in ["novalue", "=x", "1a=x", "a-b=x", "a b=x"] {
            k.copier.data = vec![bad.into()];
            assert!(k.validate().is_err(), "{bad:?} must be rejected");
        }
        k.copier = CopierOptions { data: vec![], vcs_ref: Some("--evil".into()) };
        assert!(k.validate().is_err());
        let mut other = kickoff(Engine::Wasp, None);
        other.copier.data = vec!["a=b".into()];
        assert!(other.validate().unwrap_err().to_string().contains("only apply to --engine copier"));
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
        assert_eq!(k.plan().iter().filter(|l| !l.starts_with("preflight:")).count(), 1);
        k.install = true;
        assert!(k.plan()[0].contains("uv tool install copier==9.17.0"));
        assert!(Engine::Wasp.install_argv().is_none(), "no piped shell installers");
    }

    #[test]
    fn node_engines_install_then_run_their_tool() {
        let ts = kickoff(Engine::TypeSpec, Some("main.tsp")).steps();
        assert_eq!(ts.len(), 2);
        assert!(ts[1].args.iter().any(|a| a == "tsp"));
        let zs = kickoff(Engine::ZenStack, Some("schema.zmodel")).steps();
        assert!(zs[1].args.iter().any(|a| a == "generate"));
        let pj = kickoff(Engine::Projen, None).steps();
        assert!(pj.iter().any(|s| s.args.iter().any(|a| a.starts_with("projen@"))));
        assert!(kickoff(Engine::TypeSpec, None).validate().is_err());
    }

    #[test]
    fn node_generated_headers_are_recognised() {
        assert!(is_marked_generated("# ~~ Generated by projen. To modify, edit .projenrc"));
        assert!(is_marked_generated("// DO NOT MODIFY THIS FILE\nexport {}"));
    }

    #[test]
    fn registry_is_consistent_with_the_engine_enum() {
        for engine in [Engine::Kthulu, Engine::Ferrum, Engine::Wasp, Engine::Copier, Engine::OpenApi, Engine::TypeSpec, Engine::Projen, Engine::ZenStack] {
            assert_eq!(Engine::parse(engine.spec().name).unwrap(), engine);
        }
        assert_eq!(engine_names(), ["kthulu", "ferrum", "wasp", "copier", "openapi", "typespec", "projen", "zenstack"]);
        assert!(engine_languages_text().starts_with("kthulu = Go, ferrum = Rust + React, wasp = TypeScript full-stack, copier = any Jinja template, openapi = code from an OpenAPI spec, typespec = "));
        assert_eq!(engine_for_language("Golang").unwrap().name, "kthulu");
        assert_eq!(engine_for_language("rs").unwrap().name, "ferrum");
        assert_eq!(engine_for_language("node").unwrap().name, "wasp");
        assert!(engine_for_language("cobol").is_none());
        assert!(engine_for_language("python").is_none(), "copier and openapi are not picked by language");
        assert_eq!(Engine::OpenApi.executable(), "openapi-generator-cli");
        assert_eq!(Engine::OpenApi.spec().required_args, ["name", "blueprint", "generator"]);
        assert_eq!(Engine::Copier.spec().required_args, ["name", "blueprint"]);
        assert!(Engine::OpenApi.spec().has(Capability::SpecDriven));
        assert!(Engine::Copier.spec().has(Capability::Template));
        assert_eq!(
            kickoff(Engine::Kthulu, Some("/p/plan.yaml")).regenerate_command(),
            "kthulu create shop --from-plan plan.yaml"
        );
        assert_eq!(kickoff(Engine::Kthulu, None).regenerate_command(), "kthulu generate");
        assert_eq!(
            kickoff(Engine::Ferrum, Some("/p/g.yaml")).regenerate_command(),
            "ferrum compile gen/g.yaml --output ."
        );
    }

    #[test]
    fn fullstack_refuses_wasp_as_backend() {
        let err = run_fullstack(&FullstackKickoff {
            backend: Engine::Wasp,
            name: "shop".into(),
            blueprint: None,
            generator: None,
            parent: PathBuf::from("/nonexistent"),
            install: false,
            programs: Default::default(),
            app: None,
        })
        .unwrap_err();
        assert!(err.to_string().contains("ferrum"), "{err}");
    }

    #[cfg(unix)]
    fn script(dir: &Path, name: &str, body: &str) -> String {
        use std::os::unix::fs::PermissionsExt;
        let path = dir.join(name);
        std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        path.display().to_string()
    }

    #[cfg(unix)]
    #[test]
    fn a_ferrum_app_replaces_the_seeded_users_example_and_keeps_its_description() {
        let parent = scratch("ferrum-app");
        let ferrum = script(
            &parent,
            "ferrum",
            "case \"$1\" in init) mkdir -p \"$2/gen\"; echo users > \"$2/gen/example.yaml\";; compile) mkdir -p backend; printf '// Code generated by ferrum. DO NOT EDIT.\\n' > backend/a.rs;; esac",
        );
        let app =
            crate::app_spec::AppSpec::from_entity_flags("todo", &["todo:title=string".to_string()])
                .unwrap();
        let blueprint = app_blueprint(&app, Engine::Ferrum).unwrap();
        let k = EngineKickoff {
            engine: Engine::Ferrum,
            name: "shop".into(),
            blueprint: Some(blueprint),
            parent: parent.clone(),
            program: Some(ferrum),
            generator: None,
            install: false,
            templates: Some(parent.clone()),
            copier: Default::default(),
            api_only: false,
        };
        let report = run(&k).unwrap();
        record_app(&app, &report.project_dir).unwrap();
        let dir = parent.join("shop");
        assert!(
            !dir.join("gen/example.yaml").exists(),
            "the users example is gone"
        );
        assert!(
            std::fs::read_to_string(dir.join("gen/todo.yaml"))
                .unwrap()
                .contains("listTodos")
        );
        assert!(
            std::fs::read_to_string(dir.join("app.json"))
                .unwrap()
                .contains("\"todo\"")
        );
        assert!(
            app_blueprint(&app, Engine::Kthulu)
                .unwrap_err()
                .to_string()
                .contains("--blueprint")
        );
        std::fs::remove_dir_all(&parent).ok();
    }

    #[cfg(unix)]
    #[test]
    fn fullstack_with_an_app_derives_the_contract_and_registers_it() {
        let (root, report) = fullstack_app("derived");
        let contract = std::fs::read_to_string(root.join("contract/openapi.yaml")).unwrap();
        assert!(
            contract.contains("/todos/{id}:") && contract.contains("operationId: createTodo"),
            "{contract}"
        );
        assert!(
            report
                .notes
                .iter()
                .any(|n| n.contains("derived from app.json"))
        );
        let manifest = Manifest::load(&root);
        let entry = &manifest.files["contract/openapi.yaml"];
        assert_eq!(entry.source.as_deref(), Some("app.json"));
        assert_eq!(entry.regenerate.as_deref(), Some(CONTRACT_REGENERATE));
        assert!(root.join("app.json").is_file());
        std::fs::remove_dir_all(root.parent().unwrap()).ok();
    }

    #[cfg(unix)]
    fn fullstack_app(tag: &str) -> (PathBuf, KickoffReport) {
        let parent = scratch(tag);
        let mut programs = std::collections::BTreeMap::new();
        programs.insert(
            "backend".to_string(),
            script(
                &parent,
                "back",
                "mkdir -p \"$2\" 2>/dev/null; mkdir -p backend; mkdir -p gen",
            ),
        );
        programs.insert(
            "frontend".to_string(),
            script(&parent, "front", "mkdir -p \"$2/src\""),
        );
        programs.insert(
            "client".to_string(),
            script(
                &parent,
                "npx",
                "echo 'export type paths = Record<string, never>;' > \"$5\"",
            ),
        );
        programs.insert("templates".to_string(), parent.display().to_string());
        let app = crate::app_spec::AppSpec::from_entity_flags(
            "todo",
            &["todo:title=string,done=bool".to_string()],
        )
        .unwrap();
        let report = run_fullstack(&FullstackKickoff {
            backend: Engine::Ferrum,
            name: "shop".into(),
            blueprint: None,
            generator: None,
            parent: parent.clone(),
            install: false,
            programs,
            app: Some(app),
        });
        match report {
            Ok(report) => (parent.join("shop"), report),
            Err(e) => panic!("{e:#}"),
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_failing_build_check_records_a_defect_that_blocks_done() {
        let root = scratch("build-check");
        let mut notes = Vec::new();
        run_build_check(&root, "ferrum", &["sh", "-c", "echo 'cannot find type Usuario' >&2; exit 1"], &root, &mut notes);
        assert!(notes[0].contains("DOES NOT BUILD") && notes[0].contains("Usuario"), "{notes:?}");
        let reason = crate::generator_defects::blocking_reason(&root).expect("an open defect blocks done");
        assert!(reason.contains("ferrum") && reason.contains("Usuario"), "{reason}");
        let mut notes = Vec::new();
        run_build_check(&root, "ferrum", &["true"], &root, &mut notes);
        assert!(notes[0].contains("passed"));
        std::fs::remove_dir_all(&root).ok();
    }

    #[cfg(unix)]
    fn scratch(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("vord-kickoff-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[cfg(unix)]
    #[test]
    fn a_failing_single_engine_run_removes_what_it_created_and_says_so() {
        let parent = scratch("fail-single");
        let k = EngineKickoff {
            engine: Engine::Wasp,
            name: "shop".into(),
            blueprint: None,
            parent: parent.clone(),
            program: Some(script(&parent, "boom", "mkdir -p \"$2\"; echo x > \"$2/half\"; exit 3")),
            generator: None,
            install: false,
            templates: None,
            copier: Default::default(),
            api_only: false,
        };
        let err = run(&k).unwrap_err();
        assert!(format!("{err:#}").contains("removed the partial"), "{err:#}");
        assert!(!parent.join("shop").exists());
        std::fs::remove_dir_all(&parent).ok();
    }

    #[cfg(unix)]
    #[test]
    fn a_preexisting_project_dir_is_never_removed_on_failure() {
        let parent = scratch("fail-existing");
        std::fs::create_dir_all(parent.join("shop")).unwrap();
        std::fs::write(parent.join("shop/mine.txt"), "keep").unwrap();
        let k = EngineKickoff {
            engine: Engine::Wasp,
            name: "shop".into(),
            blueprint: None,
            parent: parent.clone(),
            program: Some(script(&parent, "boom", "exit 3")),
            generator: None,
            install: false,
            templates: None,
            copier: Default::default(),
            api_only: false,
        };
        assert!(run(&k).is_err());
        assert!(parent.join("shop/mine.txt").exists());
        std::fs::remove_dir_all(&parent).ok();
    }

    #[cfg(unix)]
    #[test]
    fn fullstack_cleans_up_when_the_second_engine_fails() {
        let parent = scratch("fail-fullstack");
        let backend = script(&parent, "back", "mkdir -p \"$2/src\"; echo '// @generated' > \"$2/src/a.rs\"");
        let frontend = script(&parent, "front", "exit 7");
        let mut programs = std::collections::BTreeMap::new();
        programs.insert("backend".to_string(), backend);
        programs.insert("frontend".to_string(), frontend);
        let err = run_fullstack(&FullstackKickoff {
            backend: Engine::Ferrum,
            name: "app".into(),
            blueprint: None,
            generator: None,
            parent: parent.clone(),
            install: false,
            programs,
            app: None,
        })
        .unwrap_err();
        assert!(format!("{err:#}").contains("removed the partial"), "{err:#}");
        assert!(!parent.join("app").exists(), "no half-built tree is left behind");
        std::fs::remove_dir_all(&parent).ok();
    }

    #[cfg(unix)]
    #[test]
    fn fullstack_success_has_one_manifest_and_one_feature_scaffold() {
        let parent = scratch("ok-fullstack");
        let backend = script(&parent, "back", "mkdir -p \"$2/src\"; echo '// @generated' > \"$2/src/a.rs\"");
        let frontend = script(&parent, "front", "mkdir -p \"$2/src\"; echo '// @generated' > \"$2/src/b.ts\"");
        let mut programs = std::collections::BTreeMap::new();
        programs.insert("backend".to_string(), backend);
        programs.insert("frontend".to_string(), frontend);
        programs.insert("client".to_string(), script(&parent, "npx", "echo 'export type paths = Record<string, never>;' > \"$5\""));
        let report = run_fullstack(&FullstackKickoff {
            backend: Engine::Ferrum,
            name: "app".into(),
            blueprint: None,
            generator: None,
            parent: parent.clone(),
            install: false,
            programs,
            app: None,
        })
        .unwrap();
        let root = parent.join("app");
        assert_eq!(report.project_dir, root);
        assert!(report.notes.iter().any(|n| n.contains("empty stub")), "{:?}", report.notes);
        let schema = std::fs::read_to_string(root.join("frontend/src/api/schema.ts")).unwrap();
        assert!(is_marked_generated(&schema), "{schema}");
        let entry = &Manifest::load(&root).files["frontend/src/api/schema.ts"];
        assert_eq!(entry.source.as_deref(), Some("contract/openapi.yaml"));
        assert_eq!(entry.regenerate.as_deref(), Some(format!("cd frontend && {CLIENT_REGENERATE}").as_str()));
        assert!(root.join("features/app.feature").exists());
        assert!(!root.join("backend/features").exists() && !root.join("frontend/features").exists());
        let manifest = Manifest::load(&root);
        assert!(manifest.files.contains_key("backend/src/a.rs") && manifest.files.contains_key("frontend/src/b.ts"));
        std::fs::remove_dir_all(&parent).ok();
    }

    #[cfg(unix)]
    #[test]
    fn openapi_spec_and_version_pin_move_into_the_project_so_regeneration_runs_from_its_root() {
        let parent = scratch("openapi-stage");
        std::fs::write(parent.join("api.yaml"), "openapi: 3.0.3\n").unwrap();
        let k = EngineKickoff {
            engine: Engine::OpenApi,
            name: "client".into(),
            blueprint: Some(parent.join("api.yaml")),
            parent: parent.clone(),
            // generate -i SPEC -g GEN -o OUT, plus the wrapper's pin file in cwd.
            program: Some(script(&parent, "oag", "mkdir -p \"$7\"; echo 'x' > \"$7/api.ts\"; echo '{}' > openapitools.json")),
            generator: Some("typescript-fetch".into()),
            install: false,
            templates: None,
            copier: Default::default(),
            api_only: false,
        };
        run(&k).unwrap();
        let dir = parent.join("client");
        assert!(dir.join("spec/api.yaml").is_file(), "the spec is kept in the project");
        assert!(dir.join("openapitools.json").is_file() && !parent.join("openapitools.json").exists());
        let manifest = Manifest::load(&dir);
        assert_eq!(
            manifest.files["api.ts"].regenerate.as_deref(),
            Some("openapi-generator-cli generate -i spec/api.yaml -g typescript-fetch -o .")
        );
        assert!(!manifest.files.contains_key("spec/api.yaml"), "the spec is the blueprint, not generated output");
        std::fs::remove_dir_all(&parent).ok();
    }

    /// A fake `openapi-generator-cli generate -i S -g G -o OUT` writing what
    /// python-fastapi does: generated modules, an empty `impl` package, tests
    /// and a default ignore file. Honors the ignore file like the real one.
    #[cfg(unix)]
    fn fake_fastapi(parent: &Path) -> String {
        script(
            parent,
            "oag",
            "out=\"$7\"; mkdir -p \"$out/src/openapi_server/impl\" \"$out/src/openapi_server/apis\" \"$out/tests\"; \
             [ -f \"$out/.openapi-generator-ignore\" ] || echo '# default' > \"$out/.openapi-generator-ignore\"; \
             echo gen > \"$out/src/openapi_server/apis/pets_api.py\"; \
             grep -q 'impl/' \"$out/.openapi-generator-ignore\" || : > \"$out/src/openapi_server/impl/__init__.py\"; \
             grep -q 'tests/' \"$out/.openapi-generator-ignore\" || echo stub > \"$out/tests/test_pets_api.py\"; \
             echo '{}' > openapitools.json",
        )
    }

    #[cfg(unix)]
    #[test]
    fn python_fastapi_impl_and_tests_are_user_owned_not_locked() {
        let parent = scratch("pyfastapi");
        std::fs::write(parent.join("api.yaml"), "openapi: 3.0.3\n").unwrap();
        let k = EngineKickoff {
            engine: Engine::OpenApi,
            name: "api".into(),
            blueprint: Some(parent.join("api.yaml")),
            parent: parent.clone(),
            program: Some(fake_fastapi(&parent)),
            generator: Some("python-fastapi".into()),
            install: false,
            templates: None,
            copier: Default::default(),
            api_only: false,
        };
        run(&k).unwrap();
        let dir = parent.join("api");
        let manifest = Manifest::load(&dir);
        let locked: Vec<&String> = manifest.files.keys().collect();
        assert!(locked.iter().any(|f| f.as_str() == "src/openapi_server/apis/pets_api.py"), "{locked:?}");
        assert!(!locked.iter().any(|f| f.contains("/impl/") || f.starts_with("tests/")), "{locked:?}");
        let ignore = std::fs::read_to_string(dir.join(".openapi-generator-ignore")).unwrap();
        assert!(ignore.lines().any(|l| l == "src/*/impl/**") && ignore.lines().any(|l| l == "tests/**"), "{ignore}");
        assert_eq!(
            manifest.files["src/openapi_server/apis/pets_api.py"].regenerate.as_deref(),
            Some("openapi-generator-cli generate -i spec/api.yaml -g python-fastapi -o .")
        );
        std::fs::remove_dir_all(&parent).ok();
    }

    #[cfg(unix)]
    #[test]
    fn generators_without_user_owned_paths_lock_all_their_output() {
        let parent = scratch("userignore");
        std::fs::write(parent.join("api.yaml"), "openapi: 3.0.3\n").unwrap();
        let oag = script(
            &parent,
            "oag",
            "out=\"$7\"; mkdir -p \"$out\"; echo '# d' > \"$out/.openapi-generator-ignore\"; echo a > \"$out/a.txt\"; echo b > \"$out/b.txt\"",
        );
        let k = EngineKickoff {
            engine: Engine::OpenApi,
            name: "api".into(),
            blueprint: Some(parent.join("api.yaml")),
            parent: parent.clone(),
            program: Some(oag),
            generator: Some("rust-axum".into()),
            install: false,
            templates: None,
            copier: Default::default(),
            api_only: false,
        };
        run(&k).unwrap();
        // rust-axum has no built-in user-owned paths: both files are locked.
        let manifest = Manifest::load(&parent.join("api"));
        assert!(manifest.files.contains_key("a.txt") && manifest.files.contains_key("b.txt"));
        std::fs::remove_dir_all(&parent).ok();
    }

    #[cfg(unix)]
    #[test]
    fn spec_first_fullstack_copies_the_users_spec_as_the_contract() {
        let parent = scratch("specfirst");
        std::fs::write(parent.join("api.yaml"), "openapi: 3.0.3\ninfo: {title: mine}\n").unwrap();
        let mut programs = std::collections::BTreeMap::new();
        programs.insert("backend".to_string(), fake_fastapi(&parent));
        programs.insert("frontend".to_string(), script(&parent, "front", "mkdir -p \"$2/src\"; echo x > \"$2/src/b.ts\""));
        programs.insert("client".to_string(), script(&parent, "npx", "echo 'export type paths = Record<string, never>;' > \"$5\""));
        let report = run_fullstack(&FullstackKickoff {
            backend: Engine::OpenApi,
            name: "app".into(),
            blueprint: Some(parent.join("api.yaml")),
            generator: Some("python-fastapi".into()),
            parent: parent.clone(),
            install: false,
            programs,
            app: None,
        })
        .unwrap();
        let root = parent.join("app");
        assert_eq!(
            std::fs::read_to_string(root.join("contract/openapi.yaml")).unwrap(),
            "openapi: 3.0.3\ninfo: {title: mine}\n"
        );
        assert!(report.notes.iter().any(|n| n.contains("your spec")), "{:?}", report.notes);
        let manifest = Manifest::load(&root);
        assert_eq!(
            manifest.files["backend/src/openapi_server/apis/pets_api.py"].regenerate.as_deref(),
            Some("cd backend && openapi-generator-cli generate -i spec/api.yaml -g python-fastapi -o .")
        );
        assert!(manifest.files.keys().all(|f| !f.contains("/impl/") && !f.starts_with("backend/tests/")));
        assert!(manifest.files.contains_key("frontend/src/api/schema.ts"));
        std::fs::remove_dir_all(&parent).ok();
    }

    #[test]
    fn the_registry_carries_the_python_spec_first_recipe() {
        let text = render_engines_text();
        assert!(text.contains("recipe:       Python: spec-first: vord kickoff --engine openapi --generator python-fastapi"), "{text}");
        let plan = FullstackKickoff {
            backend: Engine::OpenApi,
            name: "app".into(),
            blueprint: Some("api.yaml".into()),
            generator: Some("python-fastapi".into()),
            parent: "/tmp".into(),
            install: false,
            programs: Default::default(),
            app: None,
        }
        .plan();
        assert!(plan.iter().any(|l| l.contains("-g python-fastapi")) && plan.iter().any(|l| l.contains("your spec verbatim")), "{plan:?}");
    }

    #[cfg(unix)]
    #[test]
    fn templ_output_is_regenerated_by_templ() {
        let parent = scratch("templ");
        let k = EngineKickoff {
            engine: Engine::Kthulu,
            name: "shop".into(),
            blueprint: None,
            parent: parent.clone(),
            program: Some(script(
                &parent,
                "k",
                "mkdir -p \"$4/v\"; printf '// Code generated by templ - DO NOT EDIT.\\npackage v\\n' > \"$4/v/a_templ.go\"; printf '// Code generated by kthulu. DO NOT EDIT.\\npackage v\\n' > \"$4/v/b.go\"",
            )),
            generator: None,
            install: false,
            templates: None,
            copier: Default::default(),
            api_only: false,
        };
        run(&k).unwrap();
        let manifest = Manifest::load(&parent.join("shop"));
        assert_eq!(manifest.files["v/a_templ.go"].regenerate.as_deref(), Some("templ generate"));
        assert_eq!(manifest.files["v/b.go"].regenerate.as_deref(), Some("kthulu generate"));
        std::fs::remove_dir_all(&parent).ok();
    }

    #[cfg(unix)]
    fn fullstack_with(tag: &str, backend_body: &str, client: &str) -> (PathBuf, KickoffReport) {
        let parent = scratch(tag);
        let mut programs = std::collections::BTreeMap::new();
        programs.insert("backend".to_string(), script(&parent, "back", backend_body));
        programs.insert("frontend".to_string(), script(&parent, "front", "mkdir -p \"$2/src\""));
        let client = if client.starts_with('/') { client.to_string() } else { script(&parent, "npx", client) };
        programs.insert("client".to_string(), client);
        let report = run_fullstack(&FullstackKickoff {
            backend: Engine::Kthulu,
            name: "app".into(),
            blueprint: None,
            generator: None,
            parent: parent.clone(),
            install: false,
            programs,
            app: None,
        })
        .unwrap();
        (parent, report)
    }

    #[cfg(unix)]
    #[test]
    fn the_backends_openapi_document_becomes_the_contract_and_feeds_the_client() {
        let (parent, report) = fullstack_with(
            "contract-copy",
            "mkdir -p \"$2/api/docs\"; echo 'openapi: 3.0.3' > \"$2/api/docs/openapi.yaml\"; echo 'openapi: x' > \"$2/openapi.yaml\"",
            "cp ../contract/openapi.yaml \"$5\"",
        );
        let root = parent.join("app");
        // the shallowest document wins
        assert_eq!(std::fs::read_to_string(root.join("contract/openapi.yaml")).unwrap(), "openapi: x\n");
        assert!(report.notes.iter().any(|n| n.contains("copied from the backend's openapi.yaml")), "{:?}", report.notes);
        let schema = std::fs::read_to_string(root.join("frontend/src/api/schema.ts")).unwrap();
        assert!(schema.starts_with("// Code generated by openapi-typescript@") && schema.contains("openapi: x"));
        std::fs::remove_dir_all(&parent).ok();
    }

    #[cfg(unix)]
    #[test]
    fn a_missing_npx_skips_the_client_with_a_message_instead_of_failing() {
        let (parent, report) = fullstack_with("no-npx", "mkdir -p \"$2\"", "/nonexistent/npx");
        let root = parent.join("app");
        assert!(!root.join("frontend/src/api/schema.ts").exists());
        assert!(!Manifest::load(&root).files.contains_key("frontend/src/api/schema.ts"));
        assert!(report.notes.iter().any(|n| n.contains("was not generated") && n.contains("openapi-typescript@")), "{:?}", report.notes);
        std::fs::remove_dir_all(&parent).ok();
    }

    #[test]
    fn a_bad_ferrum_templates_directory_is_named() {
        let mut k = kickoff(Engine::Ferrum, Some("/plans/users.yaml"));
        k.templates = None;
        assert!(k.validate().is_ok(), "the project's own templates/ may be enough");
        k.templates = Some(PathBuf::from("/nonexistent/templates"));
        assert!(k.validate().unwrap_err().to_string().contains("not a directory"));
        assert!(kickoff(Engine::Ferrum, None).validate().is_ok(), "no blueprint, no compile, no templates needed");
    }

    #[cfg(unix)]
    #[test]
    fn a_gitignored_manifest_is_reported() {
        let dir = scratch("ignored-manifest");
        let git = |args: &[&str]| {
            Command::new("git").args(args).current_dir(&dir).output().unwrap();
        };
        git(&["init", "-q"]);
        std::fs::write(dir.join(".gitignore"), ".vord/\n").unwrap();
        std::fs::create_dir_all(dir.join(".vord")).unwrap();
        std::fs::write(dir.join(".vord/generated.json"), "{}").unwrap();
        let note = manifest_ignored_note(&dir).expect("ignored manifest is reported");
        assert!(note.contains(".vord/sessions/"), "{note}");
        std::fs::write(dir.join(".gitignore"), ".vord/sessions/\n").unwrap();
        assert!(manifest_ignored_note(&dir).is_none());
        std::fs::remove_dir_all(&dir).ok();
    }
}
