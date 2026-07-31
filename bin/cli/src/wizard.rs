//! Interactive wizard: `yunq` with no subcommand, or `yunq wizard`, in a TTY.
//! Guides scope selection → scan → a next-action menu (agent prompt, guided
//! remediation, CI install) without requiring the user to know any flags.
//! Purely additive: `scan`/`fix` stay flag-driven and unchanged for
//! CI/scripting use — every mutating action here (`remediate_issue`,
//! writing the CI workflow) goes through the same code `scan`/`fix` use.

use std::collections::HashSet;
use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::process::{Command as ProcessCommand, ExitCode};

use dialoguer::theme::ColorfulTheme;
use dialoguer::{Confirm, Input, Select};
use yunq_rules_engine::{AnalysisReport, GateEvaluation, Issue, Severity};

use crate::output;

const CI_WORKFLOW_PATH: &str = ".github/workflows/yunq.yml";
const CI_ACTION_REF: &str = "pmaojo/yunq@main";

/// Resolves the chosen scope to a scan path/diff-file-list, runs the scan,
/// persists the cache, and evaluates the gate — everything `run()`'s
/// `'rescan` loop needs before it can enter the action menu.
async fn scan_for_scope(
    theme: &ColorfulTheme,
    root: &Path,
    git_root: Option<&Path>,
) -> anyhow::Result<(PathBuf, Option<Vec<String>>, AnalysisReport, GateEvaluation)> {
    let scope = prompt_scope(theme, git_root)?;
    let (scan_path, diff_files) = match scope {
        Scope::WholeRepo => (root.to_path_buf(), None),
        Scope::Diff { base } => (root.to_path_buf(), changed_files(root, &base)),
        Scope::Custom(path) => (path, None),
    };

    println!("\nAnalizando {}...", scan_path.display());
    let cache = scan_path.is_dir().then(|| {
        std::sync::Arc::new(yunq_infra_fs::FileAnalysisCache::open(
            scan_path.join(".yunq-cache.json"),
        ))
    });
    let report = yunq_cli::scan_with_cache(&scan_path, cache.clone()).await?;
    if let Some(cache) = &cache
        && let Err(e) = cache.persist()
    {
        eprintln!("warning: could not persist analysis cache: {e}");
    }
    let gate = yunq_cli::default_quality_gate().evaluate(|key| report.measure(key));

    Ok((scan_path, diff_files, report, gate))
}

pub async fn run() -> anyhow::Result<ExitCode> {
    if !is_interactive() {
        eprintln!(
            "yunq: no interactive terminal detected. Use `yunq scan <path>` or `yunq --help` for scripted/CI use."
        );
        return Ok(ExitCode::FAILURE);
    }

    let theme = ColorfulTheme::default();
    let cwd = std::env::current_dir()?;
    let git_root = yunq_cli::find_git_root(&cwd);
    let root = git_root.clone().unwrap_or_else(|| cwd.clone());

    print_welcome(&root, git_root.as_deref());

    'rescan: loop {
        let (scan_path, diff_files, report, gate) =
            scan_for_scope(&theme, &root, git_root.as_deref()).await?;

        print_summary(&report, &gate, diff_files.as_deref());

        loop {
            match action_menu(&theme, &report, git_root.as_deref())? {
                Action::AgentPrompt => {
                    println!(
                        "\n{}",
                        output::render_agent_prompt(
                            &report,
                            &gate,
                            &scan_path.display().to_string()
                        )
                    );
                }
                Action::Remediate => {
                    remediate_loop(&theme, &report, &scan_path, diff_files.as_deref()).await?;
                }
                Action::InstallCi => {
                    install_ci(&root, false)?;
                }
                Action::Rescan => continue 'rescan,
                Action::Exit => return Ok(ExitCode::SUCCESS),
            }
        }
    }
}

fn is_interactive() -> bool {
    std::io::stdout().is_terminal() && std::io::stdin().is_terminal()
}

fn print_welcome(root: &Path, git_root: Option<&Path>) {
    println!("yunq — asistente interactivo");
    println!("────────────────────────────");
    println!("Directorio: {}", root.display());
    match git_root {
        Some(git_root) => {
            if let Some(branch) = current_branch(git_root) {
                println!("Rama: {branch}");
            }
            if let Some(existing) = detect_existing_ci(git_root) {
                println!("CI: ya hay un workflow de yunq en {}", existing.display());
            }
        }
        None => println!("(no es un repositorio git — el alcance \"diff\" no estará disponible)"),
    }
    println!();
}

enum Scope {
    WholeRepo,
    Diff { base: String },
    Custom(PathBuf),
}

fn prompt_scope(theme: &ColorfulTheme, git_root: Option<&Path>) -> anyhow::Result<Scope> {
    let mut labels = vec!["Todo el repositorio".to_string()];
    let mut diff_base = None;
    if let Some(root) = git_root
        && let (Some(branch), Some(base)) = (current_branch(root), default_branch(root))
        && branch != base
    {
        labels.push(format!("Solo los cambios de `{branch}` frente a `{base}`"));
        diff_base = Some(base);
    }
    labels.push("Otra ruta...".to_string());

    let choice = Select::with_theme(theme)
        .with_prompt("¿Qué quieres analizar?")
        .items(&labels)
        .default(0)
        .interact()?;

    if choice == 0 {
        return Ok(Scope::WholeRepo);
    }
    if let Some(base) = diff_base
        && choice == 1
    {
        return Ok(Scope::Diff { base });
    }
    let raw: String = Input::with_theme(theme)
        .with_prompt("Ruta a analizar")
        .interact_text()?;
    Ok(Scope::Custom(PathBuf::from(raw)))
}

fn print_summary(report: &AnalysisReport, gate: &GateEvaluation, diff_files: Option<&[String]>) {
    let mut by_severity: std::collections::BTreeMap<Severity, usize> =
        std::collections::BTreeMap::new();
    for issue in report.issues() {
        *by_severity.entry(issue.severity()).or_default() += 1;
    }
    println!();
    println!(
        "{} issue(s) · quality gate: {}",
        report.issues().len(),
        gate.status()
    );
    for (severity, count) in by_severity.iter().rev() {
        println!("  {:<8} {count}", severity.as_str().to_uppercase());
    }
    if let Some(files) = diff_files {
        let touched = count_issues_in_files(report.issues(), files);
        println!(
            "  → {touched} de {} issues tocan archivos cambiados en esta rama.\n    (el gate mostrado es el del repo completo — este filtrado es solo informativo, no un gate de \"New Code\")",
            report.issues().len()
        );
    }
}

fn count_issues_in_files(issues: &[Issue], files: &[String]) -> usize {
    let set: HashSet<&str> = files.iter().map(String::as_str).collect();
    issues
        .iter()
        .filter(|issue| set.contains(issue.file()))
        .count()
}

enum Action {
    AgentPrompt,
    Remediate,
    InstallCi,
    Rescan,
    Exit,
}

fn action_menu(
    theme: &ColorfulTheme,
    report: &AnalysisReport,
    git_root: Option<&Path>,
) -> anyhow::Result<Action> {
    let mut labels = Vec::new();
    let mut actions = Vec::new();
    if !report.issues().is_empty() {
        labels.push("Ver el prompt para pegar en un agente de IA".to_string());
        actions.push(Action::AgentPrompt);
        labels.push("Arreglar issues con el remediador (uno a uno)".to_string());
        actions.push(Action::Remediate);
    }
    if let Some(root) = git_root
        && detect_existing_ci(root).is_none()
    {
        labels.push("Instalar yunq en CI (GitHub Actions)".to_string());
        actions.push(Action::InstallCi);
    }
    labels.push("Volver a analizar".to_string());
    actions.push(Action::Rescan);
    labels.push("Salir".to_string());
    actions.push(Action::Exit);

    let choice = Select::with_theme(theme)
        .with_prompt("¿Qué quieres hacer ahora?")
        .items(&labels)
        .default(0)
        .interact()?;
    Ok(actions.remove(choice))
}

fn issue_labels(issues: &[&Issue]) -> Vec<String> {
    let mut labels: Vec<String> = issues
        .iter()
        .map(|issue| {
            format!(
                "[{}] {} — {}:{} — {}",
                issue.severity().as_str().to_uppercase(),
                issue.rule(),
                issue.file(),
                issue.span().start_line,
                truncate(issue.message(), 60),
            )
        })
        .collect();
    labels.push("‹ volver".to_string());
    labels
}

/// Confirms and applies (or skips) an AI-verified fix for one issue.
/// Always returns `Ok` — a rejected/failed fix is reported to the user,
/// not propagated, so the caller's loop keeps offering the rest.
async fn remediate_one(
    theme: &ColorfulTheme,
    scan_path: &Path,
    issue: &Issue,
) -> anyhow::Result<()> {
    let confirmed = Confirm::with_theme(theme)
        .with_prompt(format!(
            "¿Aplicar y verificar un fix con IA para `{}` en {}:{}? Se aplica directamente al archivo y se \
             revierte solo si no verifica.",
            issue.rule(),
            issue.file(),
            issue.span().start_line,
        ))
        .default(false)
        .interact()?;
    if !confirmed {
        return Ok(());
    }

    let file_path = scan_path.join(issue.file());
    match yunq_cli::remediate_issue(&file_path, issue.rule().as_str(), None).await {
        Ok((path, yunq_remediation::RemediationVerdict::Accepted { proposal })) => {
            println!(
                "\n✅ Fix verificado y aplicado en {}:\n{}\n\nExplicación: {}",
                path.display(),
                proposal.replacement_snippet,
                proposal.explanation,
            );
        }
        Ok((_, yunq_remediation::RemediationVerdict::Rejected { reason })) => {
            eprintln!("❌ No se pudo verificar un fix: {reason}");
        }
        Err(err) => {
            eprintln!("❌ Error al intentar el fix: {err:#}");
        }
    }
    Ok(())
}

async fn remediate_loop(
    theme: &ColorfulTheme,
    report: &AnalysisReport,
    scan_path: &Path,
    diff_files: Option<&[String]>,
) -> anyhow::Result<()> {
    let mut issues: Vec<&Issue> = report.issues().iter().collect();
    issues.sort_by_key(|issue| std::cmp::Reverse(issue.severity()));
    if let Some(files) = diff_files {
        issues = touched_first(issues, files);
    }

    loop {
        if issues.is_empty() {
            println!("No hay más issues para arreglar.");
            return Ok(());
        }
        let labels = issue_labels(&issues);

        let choice = Select::with_theme(theme)
            .with_prompt("Elige un issue para arreglar")
            .items(&labels)
            .default(0)
            .interact()?;
        if choice == issues.len() {
            return Ok(());
        }

        remediate_one(theme, scan_path, issues[choice]).await?;
        // Best-effort: drop it from this session's list either way so the
        // same issue isn't offered twice without a fresh scan reloading it.
        issues.remove(choice);
    }
}

fn touched_first<'a>(mut issues: Vec<&'a Issue>, files: &[String]) -> Vec<&'a Issue> {
    let set: HashSet<&str> = files.iter().map(String::as_str).collect();
    issues.sort_by_key(|issue| !set.contains(issue.file()));
    issues
}

fn truncate(text: &str, max_chars: usize) -> String {
    if text.chars().count() <= max_chars {
        text.to_string()
    } else {
        format!("{}…", text.chars().take(max_chars).collect::<String>())
    }
}

/// Installs the yunq GitHub Action workflow into `root` (a Git repo).
/// `yes` skips the confirmation prompt — required when not running in a
/// TTY, e.g. `yunq init --yes` from a setup script.
pub fn install_ci(root: &Path, yes: bool) -> anyhow::Result<ExitCode> {
    let root = yunq_cli::find_git_root(root)
        .ok_or_else(|| anyhow::anyhow!("{} is not inside a Git repository", root.display()))?;

    if let Some(existing) = detect_existing_ci(&root) {
        println!("yunq ya está instalado en CI: {}", existing.display());
        return Ok(ExitCode::SUCCESS);
    }

    if !yes {
        if !is_interactive() {
            eprintln!(
                "yunq init: no hay terminal interactiva — repite con --yes para instalar sin confirmar."
            );
            return Ok(ExitCode::FAILURE);
        }
        println!("\n{}", ci_workflow_yaml());
        let confirmed = Confirm::with_theme(&ColorfulTheme::default())
            .with_prompt(format!("¿Escribir este workflow en {CI_WORKFLOW_PATH}?"))
            .default(true)
            .interact()?;
        if !confirmed {
            println!("Cancelado.");
            return Ok(ExitCode::SUCCESS);
        }
    }

    let target = root.join(CI_WORKFLOW_PATH);
    std::fs::create_dir_all(target.parent().expect("workflow path always has a parent"))?;
    std::fs::write(&target, ci_workflow_yaml())?;
    println!("✅ Escrito {}", target.display());
    Ok(ExitCode::SUCCESS)
}

fn detect_existing_ci(root: &Path) -> Option<PathBuf> {
    let entries = std::fs::read_dir(root.join(".github/workflows")).ok()?;
    entries
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| {
            matches!(
                path.extension().and_then(|e| e.to_str()),
                Some("yml") | Some("yaml")
            )
        })
        .find(|path| {
            std::fs::read_to_string(path).is_ok_and(|contents| workflow_mentions_yunq(&contents))
        })
}

fn workflow_mentions_yunq(contents: &str) -> bool {
    contents.contains("pmaojo/yunq")
        || contents.contains("yunq scan")
        || contents.contains("bin/yunq")
        || contents.contains("bin yunq")
}

fn ci_workflow_yaml() -> String {
    format!(
        "name: yunq\n\
         \n\
         on:\n\
         \x20 pull_request:\n\
         \x20 push:\n\
         \x20   branches: [main]\n\
         \n\
         jobs:\n\
         \x20 scan:\n\
         \x20   runs-on: ubuntu-latest\n\
         \x20   steps:\n\
         \x20     - uses: actions/checkout@v4\n\
         \x20     - uses: {CI_ACTION_REF}\n"
    )
}

fn git_output(root: &Path, args: &[&str]) -> Option<String> {
    let output = ProcessCommand::new("git")
        .arg("-C")
        .arg(root)
        .args(args)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    String::from_utf8(output.stdout)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

fn current_branch(root: &Path) -> Option<String> {
    git_output(root, &["rev-parse", "--abbrev-ref", "HEAD"]).filter(|branch| branch != "HEAD")
}

fn default_branch(root: &Path) -> Option<String> {
    if let Some(symbolic) = git_output(root, &["symbolic-ref", "refs/remotes/origin/HEAD"])
        && let Some(name) = parse_symbolic_ref(&symbolic)
    {
        return Some(name);
    }
    ["main", "master"]
        .into_iter()
        .find(|candidate| {
            git_output(
                root,
                &[
                    "rev-parse",
                    "--verify",
                    "--quiet",
                    &format!("refs/heads/{candidate}"),
                ],
            )
            .is_some()
        })
        .map(str::to_string)
}

fn parse_symbolic_ref(raw: &str) -> Option<String> {
    raw.rsplit('/')
        .next()
        .map(str::to_string)
        .filter(|s| !s.is_empty())
}

fn changed_files(root: &Path, base: &str) -> Option<Vec<String>> {
    git_output(root, &["diff", "--name-only", &format!("{base}...HEAD")])
        .map(|raw| parse_name_only(&raw))
}

fn parse_name_only(raw: &str) -> Vec<String> {
    raw.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(str::to_string)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use yunq_ast::Span;
    use yunq_rules_engine::RuleId;

    fn issue(rule: &str, file: &str) -> Issue {
        Issue::new(
            RuleId::new(rule).unwrap(),
            Severity::Major,
            "msg",
            file,
            Span::new(1, 1, 1, 1),
        )
    }

    #[test]
    fn parses_symbolic_ref_into_branch_name() {
        assert_eq!(
            parse_symbolic_ref("refs/remotes/origin/main"),
            Some("main".to_string())
        );
        assert_eq!(
            parse_symbolic_ref("refs/remotes/origin/release/1.0"),
            Some("1.0".to_string())
        );
        assert_eq!(parse_symbolic_ref(""), None);
    }

    #[test]
    fn parses_name_only_diff_output() {
        assert_eq!(
            parse_name_only("src/a.ts\nsrc/b.rs\n\n  \n"),
            vec!["src/a.ts".to_string(), "src/b.rs".to_string()]
        );
        assert_eq!(parse_name_only(""), Vec::<String>::new());
    }

    #[test]
    fn counts_issues_touching_changed_files() {
        let issues = vec![
            issue("owasp:injection", "src/a.ts"),
            issue("smells:long-function", "src/b.rs"),
        ];
        let files = vec!["src/a.ts".to_string()];
        assert_eq!(count_issues_in_files(&issues, &files), 1);
        assert_eq!(count_issues_in_files(&issues, &[]), 0);
    }

    #[test]
    fn sorts_touched_files_first_and_is_stable_within_groups() {
        let untouched = issue("owasp:injection", "src/untouched.ts");
        let touched = issue("smells:long-function", "src/touched.ts");
        let files = vec!["src/touched.ts".to_string()];
        let sorted = touched_first(vec![&untouched, &touched], &files);
        assert_eq!(sorted[0].file(), "src/touched.ts");
        assert_eq!(sorted[1].file(), "src/untouched.ts");
    }

    #[test]
    fn detects_yunq_mentions_in_workflow_contents() {
        assert!(workflow_mentions_yunq("uses: pmaojo/yunq@main"));
        assert!(workflow_mentions_yunq("run: cargo run --bin yunq scan ."));
        assert!(!workflow_mentions_yunq("uses: actions/checkout@v4"));
    }

    #[test]
    fn ci_workflow_template_references_the_published_action() {
        let yaml = ci_workflow_yaml();
        assert!(yaml.contains(CI_ACTION_REF));
        assert!(yaml.contains("pull_request"));
    }

    #[test]
    fn truncates_long_messages_with_ellipsis() {
        assert_eq!(truncate("short", 60), "short");
        assert_eq!(
            truncate(&"x".repeat(70), 60),
            format!("{}…", "x".repeat(60))
        );
    }
}
