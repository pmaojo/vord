//! Outbound adapter: reports commit statuses to GitHub's REST API. The API
//! base URL is configurable so this adapter (and its tests) can target a
//! local mock server unchanged — the same "swap the endpoint, not the code"
//! pattern used for SQS/floci.
//!
//! Auth: a token with the classic `repo:status` scope (or a fine-grained
//! PAT with "Commit statuses: write"), via `GITHUB_TOKEN` — exactly what
//! GitHub Actions injects into every workflow run for free.

use base64::Engine;
use serde::{Deserialize, Serialize};
use yunq_rules_engine::{
    AlmError, AlmPullRequestReporter, AlmStatusReporter, CommitSha, CommitStatus, Issue,
    PullRequestNumber,
};

const DEFAULT_API_BASE: &str = "https://api.github.com";
/// GitHub rejects longer commit-status descriptions; truncate defensively
/// rather than let a verbose gate summary fail the whole report.
const MAX_DESCRIPTION_LEN: usize = 140;

pub struct GitHubStatusReporter {
    client: reqwest::Client,
    token: String,
    owner: String,
    repo: String,
    api_base: String,
}

impl GitHubStatusReporter {
    pub fn new(token: impl Into<String>, owner: impl Into<String>, repo: impl Into<String>) -> Self {
        Self {
            client: reqwest::Client::new(),
            token: token.into(),
            owner: owner.into(),
            repo: repo.into(),
            api_base: DEFAULT_API_BASE.to_string(),
        }
    }

    /// Builds a reporter from the environment GitHub Actions provides:
    /// `GITHUB_TOKEN` and `GITHUB_REPOSITORY` (`owner/repo`). `None` if
    /// either is missing or malformed — callers decide whether that's fatal.
    pub fn from_env() -> Option<Self> {
        let token = std::env::var("GITHUB_TOKEN").ok()?;
        let repository = std::env::var("GITHUB_REPOSITORY").ok()?;
        let (owner, repo) = repository.split_once('/')?;
        let mut reporter = Self::new(token, owner, repo);
        if let Ok(base) = std::env::var("YUNQ_GITHUB_API_BASE") {
            reporter.api_base = base;
        }
        Some(reporter)
    }

    /// Points this reporter at a different API base (mock servers in tests,
    /// or a GitHub Enterprise Server instance in production).
    pub fn with_api_base(mut self, base: impl Into<String>) -> Self {
        self.api_base = base.into();
        self
    }

    /// Fetches a file's content via the Contents API, at `git_ref` if given
    /// or the repository's default branch otherwise. Used by the
    /// Remediation Agent to read real source when it has no local checkout
    /// to read from (the server persists issues in Postgres, never the
    /// source tree they came from).
    pub async fn fetch_file_content(
        &self,
        path: &str,
        git_ref: Option<&str>,
    ) -> Result<String, AlmError> {
        let url = match git_ref {
            Some(git_ref) => format!(
                "{}/repos/{}/{}/contents/{}?ref={}",
                self.api_base, self.owner, self.repo, path, git_ref
            ),
            None => format!("{}/repos/{}/{}/contents/{}", self.api_base, self.owner, self.repo, path),
        };
        let response = self
            .client
            .get(&url)
            .bearer_auth(&self.token)
            .header("Accept", "application/vnd.github+json")
            .header("User-Agent", "yunq")
            .send()
            .await
            .map_err(|e| AlmError(e.to_string()))?;

        if !response.status().is_success() {
            let status_code = response.status();
            let text = response.text().await.unwrap_or_default();
            return Err(AlmError(format!("GitHub returned {status_code}: {text}")));
        }

        let parsed: ContentsResponse = response
            .json()
            .await
            .map_err(|e| AlmError(format!("failed to parse GitHub contents response: {e}")))?;

        if parsed.encoding != "base64" {
            return Err(AlmError(format!(
                "unsupported GitHub contents encoding {:?}",
                parsed.encoding
            )));
        }

        let decoded = base64::engine::general_purpose::STANDARD
            .decode(parsed.content.replace('\n', ""))
            .map_err(|e| AlmError(format!("failed to decode base64 file content: {e}")))?;

        String::from_utf8(decoded)
            .map_err(|e| AlmError(format!("file content is not valid UTF-8: {e}")))
    }
}

#[derive(Deserialize)]
struct ContentsResponse {
    content: String,
    encoding: String,
}

#[derive(Serialize)]
struct StatusRequest<'a> {
    state: &'a str,
    description: &'a str,
    context: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    target_url: Option<&'a str>,
}

#[derive(Serialize)]
struct PullRequestCommentRequest<'a> {
    commit_id: &'a str,
    path: &'a str,
    line: u32,
    body: String,
}

#[derive(Deserialize)]
struct PullRequestCommentResponse {
    path: String,
    line: Option<u32>,
    body: String,
}

#[derive(Deserialize)]
struct IssueCommentResponse {
    id: u64,
    body: String,
}

#[derive(Serialize)]
struct IssueCommentRequest {
    body: String,
}

impl AlmPullRequestReporter for GitHubStatusReporter {
    async fn report_pull_request_review(
        &self,
        pr_number: PullRequestNumber,
        commit_sha: &CommitSha,
        new_issues: &[Issue],
        gate_summary: &str,
    ) -> Result<(), AlmError> {
        let pr = pr_number.get();

        // 1. Fetch existing PR review comments to avoid duplicates.
        let comments_url = format!("{}/repos/{}/{}/pulls/{}/comments", self.api_base, self.owner, self.repo, pr);
        let existing_comments: Vec<PullRequestCommentResponse> = self
            .client
            .get(&format!("{}?per_page=100", comments_url))
            .bearer_auth(&self.token)
            .header("Accept", "application/vnd.github+json")
            .header("User-Agent", "yunq")
            .send()
            .await
            .map_err(|e| AlmError(e.to_string()))?
            .json()
            .await
            .unwrap_or_default(); // Ignore fetch failure by returning empty (may result in dupes, but better than complete failure)

        let mut fallback_issues = Vec::new();

        for issue in new_issues {
            let body = format!("**{}**\n{}", issue.rule(), issue.message());

            // Check for duplicates
            if existing_comments.iter().any(|c| {
                c.path == issue.file() && c.line == Some(issue.span().start_line) && c.body.contains(issue.rule().as_str())
            }) {
                continue;
            }

            let req_body = PullRequestCommentRequest {
                commit_id: commit_sha.as_str(),
                path: issue.file(),
                line: issue.span().start_line,
                body: body.clone(),
            };

            let response = self
                .client
                .post(&comments_url)
                .bearer_auth(&self.token)
                .header("Accept", "application/vnd.github+json")
                .header("User-Agent", "yunq")
                .json(&req_body)
                .send()
                .await
                .map_err(|e| AlmError(e.to_string()))?;

            if !response.status().is_success() {
                // If it's a 422 Unprocessable Entity, it usually means the line is outside the PR diff.
                if response.status() == reqwest::StatusCode::UNPROCESSABLE_ENTITY {
                    fallback_issues.push(issue.clone());
                } else {
                    let status_code = response.status();
                    let text = response.text().await.unwrap_or_default();
                    return Err(AlmError(format!("GitHub returned {status_code}: {text}")));
                }
            }
        }

        // Handle fallback and general summary
        let mut general_body = format!("<!-- yunq-pr-comment -->\n{}\n\n", gate_summary);
        if !fallback_issues.is_empty() {
            general_body.push_str("### ⚠️ Issues outside the pull request diff\n\n");
            for issue in &fallback_issues {
                general_body.push_str(&format!("- **{}** in `{}:{}`: {}\n", issue.rule(), issue.file(), issue.span().start_line, issue.message()));
            }
        }

        let issue_comments_url = format!("{}/repos/{}/{}/issues/{}/comments", self.api_base, self.owner, self.repo, pr);

        let existing_issue_comments: Vec<IssueCommentResponse> = self
            .client
            .get(&format!("{}?per_page=100", issue_comments_url))
            .bearer_auth(&self.token)
            .header("Accept", "application/vnd.github+json")
            .header("User-Agent", "yunq")
            .send()
            .await
            .map_err(|e| AlmError(e.to_string()))?
            .json()
            .await
            .unwrap_or_default();

        let existing_comment = existing_issue_comments.iter().find(|c| c.body.contains("<!-- yunq-pr-comment -->"));

        let req_body = IssueCommentRequest { body: general_body };

        let response = if let Some(existing) = existing_comment {
            let update_url = format!("{}/repos/{}/{}/issues/comments/{}", self.api_base, self.owner, self.repo, existing.id);
            self.client
                .patch(&update_url)
                .bearer_auth(&self.token)
                .header("Accept", "application/vnd.github+json")
                .header("User-Agent", "yunq")
                .json(&req_body)
                .send()
                .await
                .map_err(|e| AlmError(e.to_string()))?
        } else {
            self.client
                .post(&issue_comments_url)
                .bearer_auth(&self.token)
                .header("Accept", "application/vnd.github+json")
                .header("User-Agent", "yunq")
                .json(&req_body)
                .send()
                .await
                .map_err(|e| AlmError(e.to_string()))?
        };

        if !response.status().is_success() {
            let status_code = response.status();
            let text = response.text().await.unwrap_or_default();
            return Err(AlmError(format!("GitHub returned {status_code}: {text}")));
        }

        Ok(())
    }
}

impl AlmStatusReporter for GitHubStatusReporter {
    async fn report_commit_status(
        &self,
        sha: &CommitSha,
        status: &CommitStatus,
    ) -> Result<(), AlmError> {
        let mut description = status.description.clone();
        if description.len() > MAX_DESCRIPTION_LEN {
            description.truncate(MAX_DESCRIPTION_LEN);
        }
        let body = StatusRequest {
            state: status.state.as_str(),
            description: &description,
            context: &status.context,
            target_url: status.target_url.as_deref(),
        };

        let url =
            format!("{}/repos/{}/{}/statuses/{}", self.api_base, self.owner, self.repo, sha);
        let response = self
            .client
            .post(&url)
            .bearer_auth(&self.token)
            .header("Accept", "application/vnd.github+json")
            .header("User-Agent", "yunq")
            .json(&body)
            .send()
            .await
            .map_err(|e| AlmError(e.to_string()))?;

        if !response.status().is_success() {
            let status_code = response.status();
            let text = response.text().await.unwrap_or_default();
            return Err(AlmError(format!("GitHub returned {status_code}: {text}")));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use axum::extract::{Path, State};
    use axum::http::{HeaderMap, StatusCode};
    use axum::routing::post;
    use axum::{Json, Router};
    use yunq_rules_engine::CommitStatusState;

    use super::*;

    #[derive(Clone, Default)]
    struct Captured {
        requests: Arc<Mutex<Vec<(String, serde_json::Value, HeaderMap)>>>,
    }

    async fn capture_status(
        State(state): State<Captured>,
        Path((owner, repo, sha)): Path<(String, String, String)>,
        headers: HeaderMap,
        Json(body): Json<serde_json::Value>,
    ) -> StatusCode {
        state.requests.lock().unwrap().push((format!("{owner}/{repo}/{sha}"), body, headers));
        StatusCode::CREATED
    }

    async fn start_mock_server() -> (String, Captured) {
        let state = Captured::default();
        let app = Router::new()
            .route("/repos/{owner}/{repo}/statuses/{sha}", post(capture_status))
            .with_state(state.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (format!("http://{addr}"), state)
    }

    #[tokio::test]
    async fn posts_status_with_expected_shape_and_auth() {
        let (base, captured) = start_mock_server().await;
        let reporter =
            GitHubStatusReporter::new("test-token", "acme", "widgets").with_api_base(base);
        let sha = CommitSha::new("a1b2c3d4e5f60718293a4b5c6d7e8f9a0b1c2d3e").unwrap();
        let status = CommitStatus::new(CommitStatusState::Failure, "quality gate failed")
            .with_target_url("https://ci.example.com/build/42");

        reporter.report_commit_status(&sha, &status).await.unwrap();

        let requests = captured.requests.lock().unwrap();
        assert_eq!(requests.len(), 1);
        let (path, body, headers) = &requests[0];
        assert_eq!(path, &format!("acme/widgets/{sha}"));
        assert_eq!(body["state"], "failure");
        assert_eq!(body["description"], "quality gate failed");
        assert_eq!(body["context"], "yunq");
        assert_eq!(body["target_url"], "https://ci.example.com/build/42");
        assert_eq!(headers.get("authorization").unwrap(), "Bearer test-token");
    }

    #[tokio::test]
    async fn truncates_overlong_description() {
        let (base, captured) = start_mock_server().await;
        let reporter = GitHubStatusReporter::new("t", "o", "r").with_api_base(base);
        let sha = CommitSha::new("a1b2c3d").unwrap();
        let long = "x".repeat(200);
        let status = CommitStatus::new(CommitStatusState::Success, long);

        reporter.report_commit_status(&sha, &status).await.unwrap();

        let requests = captured.requests.lock().unwrap();
        assert_eq!(requests[0].1["description"].as_str().unwrap().len(), MAX_DESCRIPTION_LEN);
    }

    #[test]
    fn from_env_parses_owner_repo() {
        // SAFETY: single-threaded test, no concurrent env access.
        unsafe {
            std::env::set_var("GITHUB_TOKEN", "tok");
            std::env::set_var("GITHUB_REPOSITORY", "acme/widgets");
        }
        let reporter = GitHubStatusReporter::from_env().unwrap();
        assert_eq!(reporter.owner, "acme");
        assert_eq!(reporter.repo, "widgets");
        unsafe {
            std::env::remove_var("GITHUB_TOKEN");
            std::env::remove_var("GITHUB_REPOSITORY");
        }
    }

    async fn serve_content(body: serde_json::Value) -> String {
        let app = Router::new()
            .route(
                "/repos/{owner}/{repo}/contents/{*path}",
                axum::routing::get(move || {
                    let body = body.clone();
                    async move { Json(body) }
                }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        format!("http://{addr}")
    }

    #[tokio::test]
    async fn fetch_file_content_decodes_base64_response() {
        let source = "fn main() {\n    eval(input);\n}\n";
        let encoded = base64::engine::general_purpose::STANDARD.encode(source);
        let base = serve_content(serde_json::json!({
            "content": encoded,
            "encoding": "base64",
        }))
        .await;

        let reporter = GitHubStatusReporter::new("t", "acme", "widgets").with_api_base(base);
        let content = reporter.fetch_file_content("src/main.rs", Some("abc123")).await.unwrap();

        assert_eq!(content, source);
    }

    #[tokio::test]
    async fn fetch_file_content_rejects_non_base64_encoding() {
        let base = serve_content(serde_json::json!({
            "content": "not really",
            "encoding": "none",
        }))
        .await;

        let reporter = GitHubStatusReporter::new("t", "acme", "widgets").with_api_base(base);
        let err = reporter.fetch_file_content("src/main.rs", Some("abc123")).await.unwrap_err();

        assert!(err.0.contains("unsupported"), "unexpected error: {}", err.0);
    }
}
