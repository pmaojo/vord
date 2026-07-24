//! CI auto-detection: fills `--commit-sha`/`--branch`/`--pr`/`--github-repo`
//! from well-known CI provider environment variables when the corresponding
//! flag wasn't given explicitly on the command line. An explicit flag always
//! wins — [`CiContext`] only supplies *defaults*.
//!
//! [`detect_ci_context`] is pure: it takes an injected environment lookup
//! (`&impl Fn(&str) -> Option<String>`) instead of reading `std::env`
//! directly, so it's fully unit-testable without mutating real process
//! state. The one piece of CI detection that needs a file read — GitHub
//! Actions' `GITHUB_EVENT_PATH` JSON, which carries the PR number on some
//! event shapes `GITHUB_REF` doesn't — is split into a pure JSON parser
//! ([`parse_pr_number_from_github_event`]) that the adapter (`main.rs`)
//! calls after doing the actual file read.

/// Which CI provider was detected, if any.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CiProvider {
    GithubActions,
    GitlabCi,
}

/// Scan identity/target defaults inferred from the CI environment. Every
/// field is `None` when it couldn't be determined — callers fall back to
/// whatever they already had.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CiContext {
    pub provider: Option<CiProvider>,
    pub commit_sha: Option<String>,
    pub branch: Option<String>,
    pub pr: Option<u32>,
    /// GitHub-specific `owner/repo` slug — only populated on GitHub Actions,
    /// since it feeds `--github-repo` (the GitHub status-reporting flag).
    pub github_repo: Option<String>,
}

/// Detects CI context from an injected environment lookup. Checks GitHub
/// Actions first, then GitLab CI; returns an empty [`CiContext`] when
/// neither is detected.
pub fn detect_ci_context(env: &impl Fn(&str) -> Option<String>) -> CiContext {
    if env("GITHUB_ACTIONS").as_deref() == Some("true") {
        return detect_github_actions(env);
    }
    if env("GITLAB_CI").as_deref() == Some("true") {
        return detect_gitlab_ci(env);
    }
    CiContext::default()
}

/// `refs/pull/42/merge` -> `42`; anything else (branch/tag refs, or a
/// missing ref) -> `None`.
fn pr_number_from_github_ref(github_ref: &str) -> Option<u32> {
    github_ref.strip_prefix("refs/pull/").and_then(|rest| rest.split('/').next()).and_then(|s| s.parse().ok())
}

/// `refs/heads/main` -> `main`; `refs/tags/v1`/`refs/pull/...` -> `None`
/// (not a branch).
fn branch_from_github_ref(github_ref: &str) -> Option<String> {
    github_ref.strip_prefix("refs/heads/").map(str::to_string)
}

fn detect_github_actions(env: &impl Fn(&str) -> Option<String>) -> CiContext {
    let github_ref = env("GITHUB_REF").unwrap_or_default();
    // On a `pull_request` event GITHUB_REF is the ephemeral merge ref
    // (refs/pull/N/merge); GITHUB_HEAD_REF carries the PR's real source
    // branch name and is only set in that case, so prefer it.
    let branch = env("GITHUB_HEAD_REF")
        .filter(|s| !s.is_empty())
        .or_else(|| branch_from_github_ref(&github_ref));
    CiContext {
        provider: Some(CiProvider::GithubActions),
        commit_sha: env("GITHUB_SHA"),
        branch,
        pr: pr_number_from_github_ref(&github_ref),
        github_repo: env("GITHUB_REPOSITORY"),
    }
}

fn detect_gitlab_ci(env: &impl Fn(&str) -> Option<String>) -> CiContext {
    // CI_COMMIT_BRANCH is only set for branch pipelines (empty for MR/tag
    // pipelines), so prefer the MR source branch when this is an MR
    // pipeline, then fall back through the more general ref name.
    let branch = env("CI_MERGE_REQUEST_SOURCE_BRANCH_NAME")
        .or_else(|| env("CI_COMMIT_BRANCH"))
        .or_else(|| env("CI_COMMIT_REF_NAME"));
    CiContext {
        provider: Some(CiProvider::GitlabCi),
        commit_sha: env("CI_COMMIT_SHA"),
        branch,
        pr: env("CI_MERGE_REQUEST_IID").and_then(|s| s.parse().ok()),
        github_repo: None,
    }
}

/// Extracts a pull request number from a GitHub Actions `GITHUB_EVENT_PATH`
/// webhook payload's JSON text — the fallback for event shapes where
/// `GITHUB_REF` alone doesn't carry the PR number (e.g. `issue_comment` on a
/// PR). Looks for `.pull_request.number` first, then a bare `.number`
/// (present on `pull_request`/`pull_request_target` payloads at top level).
/// Deliberately hand-rolled (no `serde_json::Value` needed) since this is
/// the only field the CLI cares about here.
pub fn parse_pr_number_from_github_event(json: &str) -> Option<u32> {
    let value: serde_json::Value = serde_json::from_str(json).ok()?;
    value
        .get("pull_request")
        .and_then(|pr| pr.get("number"))
        .or_else(|| value.get("number"))
        .and_then(|n| n.as_u64())
        .and_then(|n| u32::try_from(n).ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn env_from(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let map: HashMap<String, String> =
            pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        move |key: &str| map.get(key).cloned()
    }

    #[test]
    fn detects_github_actions_push_event() {
        let env = env_from(&[
            ("GITHUB_ACTIONS", "true"),
            ("GITHUB_SHA", "abc1234abc1234abc1234abc1234abc1234abcd"),
            ("GITHUB_REF", "refs/heads/main"),
            ("GITHUB_REPOSITORY", "pmaojo/yunq"),
        ]);
        let ctx = detect_ci_context(&env);
        assert_eq!(ctx.provider, Some(CiProvider::GithubActions));
        assert_eq!(ctx.commit_sha.as_deref(), Some("abc1234abc1234abc1234abc1234abc1234abcd"));
        assert_eq!(ctx.branch.as_deref(), Some("main"));
        assert_eq!(ctx.pr, None);
        assert_eq!(ctx.github_repo.as_deref(), Some("pmaojo/yunq"));
    }

    #[test]
    fn detects_github_actions_pull_request_event() {
        let env = env_from(&[
            ("GITHUB_ACTIONS", "true"),
            ("GITHUB_SHA", "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"),
            ("GITHUB_REF", "refs/pull/42/merge"),
            ("GITHUB_HEAD_REF", "feature/ergonomics"),
            ("GITHUB_REPOSITORY", "pmaojo/yunq"),
        ]);
        let ctx = detect_ci_context(&env);
        assert_eq!(ctx.branch.as_deref(), Some("feature/ergonomics"));
        assert_eq!(ctx.pr, Some(42));
    }

    #[test]
    fn detects_gitlab_ci_merge_request_pipeline() {
        let env = env_from(&[
            ("GITLAB_CI", "true"),
            ("CI_COMMIT_SHA", "cafebabecafebabecafebabecafebabecafebabe"),
            ("CI_MERGE_REQUEST_SOURCE_BRANCH_NAME", "feature/x"),
            ("CI_MERGE_REQUEST_IID", "7"),
        ]);
        let ctx = detect_ci_context(&env);
        assert_eq!(ctx.provider, Some(CiProvider::GitlabCi));
        assert_eq!(ctx.commit_sha.as_deref(), Some("cafebabecafebabecafebabecafebabecafebabe"));
        assert_eq!(ctx.branch.as_deref(), Some("feature/x"));
        assert_eq!(ctx.pr, Some(7));
        assert_eq!(ctx.github_repo, None);
    }

    #[test]
    fn detects_gitlab_ci_branch_pipeline() {
        let env = env_from(&[
            ("GITLAB_CI", "true"),
            ("CI_COMMIT_SHA", "cafebabecafebabecafebabecafebabecafebabe"),
            ("CI_COMMIT_BRANCH", "main"),
        ]);
        let ctx = detect_ci_context(&env);
        assert_eq!(ctx.branch.as_deref(), Some("main"));
        assert_eq!(ctx.pr, None);
    }

    #[test]
    fn no_ci_detected_yields_empty_context() {
        let env = env_from(&[]);
        let ctx = detect_ci_context(&env);
        assert_eq!(ctx, CiContext::default());
        assert_eq!(ctx.provider, None);
    }

    #[test]
    fn explicit_env_wins_over_absent_ci_markers() {
        // GITHUB_SHA present but GITHUB_ACTIONS not "true" -> not detected.
        let env = env_from(&[("GITHUB_SHA", "abc1234")]);
        assert_eq!(detect_ci_context(&env), CiContext::default());
    }

    #[test]
    fn parses_pr_number_from_pull_request_event_payload() {
        let json = r#"{"action":"opened","number":42,"pull_request":{"number":42,"title":"x"}}"#;
        assert_eq!(parse_pr_number_from_github_event(json), Some(42));
    }

    #[test]
    fn parses_pr_number_from_top_level_number_when_no_pull_request_key() {
        let json = r#"{"number":9}"#;
        assert_eq!(parse_pr_number_from_github_event(json), Some(9));
    }

    #[test]
    fn returns_none_for_push_event_payload_without_a_pr_number() {
        let json = r#"{"ref":"refs/heads/main","commits":[]}"#;
        assert_eq!(parse_pr_number_from_github_event(json), None);
    }

    #[test]
    fn returns_none_for_invalid_json() {
        assert_eq!(parse_pr_number_from_github_event("not json"), None);
    }
}
