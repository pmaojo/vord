//! Verifying the API contract: lint it (Redocly) and, given a running
//! server, test the server against it (Schemathesis). A failure is recorded
//! as a defect, so `vord agent done` waits until it is fixed.

use std::path::Path;
use std::process::Command;

pub const REDOCLY: &str = "@redocly/cli@2.57.0";
pub const SCHEMATHESIS: &str = "schemathesis==4.29.2";
pub const SPEC: &str = "contract/openapi.yaml";

/// `redocly.yaml` kickoff writes next to the contract: the recommended
/// rules, minus the two that cannot hold for a fresh local project.
pub const REDOCLY_CONFIG: &str = "extends:\n  - recommended\nrules:\n  info-license-strict: off\n  no-server-example.com: off\n";

pub struct Outcome {
    pub name: &'static str,
    pub passed: bool,
    pub detail: String,
}

fn tail(text: &str, lines: usize) -> String {
    let all: Vec<&str> = text.lines().filter(|l| !l.trim().is_empty()).collect();
    all[all.len().saturating_sub(lines)..].join(" | ")
}

fn available(program: &str) -> bool {
    std::env::var_os("PATH").is_some_and(|paths| std::env::split_paths(&paths).any(|dir| dir.join(program).is_file()))
}

fn run(name: &'static str, mut command: Command) -> Outcome {
    match command.output() {
        Ok(out) => Outcome {
            name,
            passed: out.status.success(),
            detail: tail(&format!("{}\n{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr)), 12),
        },
        Err(e) => Outcome { name, passed: false, detail: format!("could not run: {e}") },
    }
}

/// Lints the contract with Redocly (needs `npx`).
pub fn lint(root: &Path, spec: &str) -> Outcome {
    if !available("npx") {
        return Outcome { name: "contract lint", passed: true, detail: "skipped: npx is not on PATH".into() };
    }
    let mut command = Command::new("npx");
    command.args(["-y", REDOCLY, "lint", spec]).current_dir(root);
    run("contract lint", command)
}

/// Tests a running server against the contract with Schemathesis (needs `uvx`).
pub fn test_server(root: &Path, spec: &str, url: &str) -> Outcome {
    if !available("uvx") {
        return Outcome { name: "contract test", passed: true, detail: "skipped: uvx (uv) is not on PATH".into() };
    }
    let mut command = Command::new("uvx");
    command.args(["--from", SCHEMATHESIS, "st", "run", spec, "--url", url]).current_dir(root);
    run("contract test", command)
}

/// Runs the checks and records each failure as a defect of the contract.
pub fn verify(root: &Path, spec: &str, url: Option<&str>) -> Vec<Outcome> {
    let mut outcomes = vec![lint(root, spec)];
    if let Some(url) = url {
        outcomes.push(test_server(root, spec, url));
    }
    for outcome in outcomes.iter().filter(|o| !o.passed) {
        let _ = crate::generator_defects::report(root, "contract", spec, &format!("{} fails: {}", outcome.name, outcome.detail));
    }
    outcomes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_failing_check_is_reported_with_its_output_tail() {
        let outcome = run("x", {
            let mut c = Command::new("sh");
            c.args(["-c", "echo one; echo two >&2; exit 1"]);
            c
        });
        assert!(!outcome.passed);
        assert_eq!(outcome.detail, "one | two");
    }
}
