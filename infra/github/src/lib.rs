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
    pub fn new(
        token: impl Into<String>,
        owner: impl Into<String>,
        repo: impl Into<String>,
    ) -> Self {
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
            None => format!(
                "{}/repos/{}/{}/contents/{}",
                self.api_base, self.owner, self.repo, path
            ),
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
    /// Where `line` was before the comment's diff position went stale
    /// (further commits pushed to the PR). Once that happens GitHub sets
    /// `line` to `null` and only `original_line` still says where the
    /// comment was — dedup has to check both or it starts re-posting the
    /// same issue on every subsequent push, which is the common case for a
    /// reporter that runs on every CI run.
    original_line: Option<u32>,
    body: String,
}

impl PullRequestCommentResponse {
    fn line_number(&self) -> Option<u32> {
        self.line.or(self.original_line)
    }
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

/// The general summary comment body: the yunq marker + gate summary, plus
/// (when non-empty) a bulleted list of issues that fell outside the PR diff.
fn build_summary_body(gate_summary: &str, fallback_issues: &[Issue]) -> String {
    let mut body = format!("<!-- yunq-pr-comment -->\n{}\n\n", gate_summary);
    if !fallback_issues.is_empty() {
        body.push_str("### ⚠️ Issues outside the pull request diff\n\n");
        for issue in fallback_issues {
            body.push_str(&format!(
                "- **{}** in `{}:{}`: {}\n",
                issue.rule(),
                issue.file(),
                issue.span().start_line,
                issue.message()
            ));
        }
    }
    body
}

#[derive(Deserialize)]
struct PullRequestResponse {
    head: PullRequestHead,
}

#[derive(Deserialize)]
struct PullRequestHead {
    sha: String,
}

impl GitHubStatusReporter {
    /// Fetches every page of a paginated GitHub list endpoint, propagating
    /// the first non-success response or parse failure as an error rather
    /// than silently treating it as "no results" — a failed fetch here
    /// must not be mistaken for "no existing comments", or dedup starts
    /// reposting duplicates every run.
    async fn get_all_pages<T>(&self, url: &str) -> Result<Vec<T>, AlmError>
    where
        T: for<'de> Deserialize<'de>,
    {
        let mut all = Vec::new();
        let mut page = 1u32;
        loop {
            let response = self
                .client
                .get(format!("{url}?per_page=100&page={page}"))
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

            let batch: Vec<T> = response
                .json()
                .await
                .map_err(|e| AlmError(format!("failed to parse GitHub response: {e}")))?;

            let got = batch.len();
            all.extend(batch);
            if got < 100 {
                break;
            }
            page += 1;
        }
        Ok(all)
    }

    /// The head SHA of an open pull request. `GITHUB_SHA` on `pull_request`
    /// CI events is the ephemeral merge commit, not a commit that belongs
    /// to the PR's own history — GitHub's create-review-comment endpoint
    /// requires a commit that is actually part of the pull request, so the
    /// real head has to be looked up rather than trusted from the caller.
    async fn fetch_pr_head_sha(&self, pr: u32) -> Result<String, AlmError> {
        let url = format!(
            "{}/repos/{}/{}/pulls/{}",
            self.api_base, self.owner, self.repo, pr
        );
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

        let parsed: PullRequestResponse = response
            .json()
            .await
            .map_err(|e| AlmError(format!("failed to parse GitHub pull request response: {e}")))?;
        Ok(parsed.head.sha)
    }
}

impl GitHubStatusReporter {
    /// Posts one review comment for `issue` at `commit_id`, skipping it if
    /// an equivalent comment already exists (same path/line/rule). Returns
    /// `Some(issue)` when GitHub rejected the comment as outside the PR
    /// diff (422) — the caller folds those into the general summary
    /// instead — and propagates any other failure.
    async fn post_issue_review_comment(
        &self,
        comments_url: &str,
        commit_id: &str,
        existing_comments: &[PullRequestCommentResponse],
        issue: &Issue,
    ) -> Result<Option<Issue>, AlmError> {
        let body = format!("**{}**\n{}", issue.rule(), issue.message());

        if existing_comments.iter().any(|c| {
            c.path == issue.file()
                && c.line_number() == Some(issue.span().start_line)
                && c.body.contains(issue.rule().as_str())
        }) {
            return Ok(None);
        }

        let req_body = PullRequestCommentRequest {
            commit_id,
            path: issue.file(),
            line: issue.span().start_line,
            body: body.clone(),
        };

        let response = self
            .client
            .post(comments_url)
            .bearer_auth(&self.token)
            .header("Accept", "application/vnd.github+json")
            .header("User-Agent", "yunq")
            .json(&req_body)
            .send()
            .await
            .map_err(|e| AlmError(e.to_string()))?;

        if response.status().is_success() {
            return Ok(None);
        }
        if response.status() == reqwest::StatusCode::UNPROCESSABLE_ENTITY {
            return Ok(Some(issue.clone()));
        }
        let status_code = response.status();
        let text = response.text().await.unwrap_or_default();
        Err(AlmError(format!("GitHub returned {status_code}: {text}")))
    }

    /// Sends `req_body` as a PATCH to `existing`'s comment when one is
    /// given, else as a POST creating a new comment at `issue_comments_url`.
    async fn send_summary_comment(
        &self,
        existing: Option<&IssueCommentResponse>,
        issue_comments_url: &str,
        req_body: &IssueCommentRequest,
    ) -> Result<reqwest::Response, AlmError> {
        let request = match existing {
            Some(existing) => {
                let update_url = format!(
                    "{}/repos/{}/{}/issues/comments/{}",
                    self.api_base, self.owner, self.repo, existing.id
                );
                self.client.patch(&update_url)
            }
            None => self.client.post(issue_comments_url),
        };
        request
            .bearer_auth(&self.token)
            .header("Accept", "application/vnd.github+json")
            .header("User-Agent", "yunq")
            .json(req_body)
            .send()
            .await
            .map_err(|e| AlmError(e.to_string()))
    }

    /// Creates or updates the single yunq-tagged general summary comment on
    /// the PR (identified by the `<!-- yunq-pr-comment -->` marker),
    /// listing any issues that fell outside the diff.
    async fn upsert_summary_comment(
        &self,
        pr: u32,
        gate_summary: &str,
        fallback_issues: &[Issue],
    ) -> Result<(), AlmError> {
        let general_body = build_summary_body(gate_summary, fallback_issues);

        let issue_comments_url = format!(
            "{}/repos/{}/{}/issues/{}/comments",
            self.api_base, self.owner, self.repo, pr
        );
        let existing_issue_comments: Vec<IssueCommentResponse> =
            self.get_all_pages(&issue_comments_url).await?;
        let existing_comment = existing_issue_comments
            .iter()
            .find(|c| c.body.contains("<!-- yunq-pr-comment -->"));

        let req_body = IssueCommentRequest { body: general_body };
        let response = self
            .send_summary_comment(existing_comment, &issue_comments_url, &req_body)
            .await?;

        if !response.status().is_success() {
            let status_code = response.status();
            let text = response.text().await.unwrap_or_default();
            return Err(AlmError(format!("GitHub returned {status_code}: {text}")));
        }

        Ok(())
    }
}

impl AlmPullRequestReporter for GitHubStatusReporter {
    async fn report_pull_request_review(
        &self,
        pr_number: PullRequestNumber,
        new_issues: &[Issue],
        gate_summary: &str,
    ) -> Result<(), AlmError> {
        let pr = pr_number.get();
        let commit_id = self.fetch_pr_head_sha(pr).await?;

        // 1. Fetch existing PR review comments to avoid duplicates.
        let comments_url = format!(
            "{}/repos/{}/{}/pulls/{}/comments",
            self.api_base, self.owner, self.repo, pr
        );
        let existing_comments: Vec<PullRequestCommentResponse> =
            self.get_all_pages(&comments_url).await?;

        let mut fallback_issues = Vec::new();
        for issue in new_issues {
            if let Some(fallback) = self
                .post_issue_review_comment(&comments_url, &commit_id, &existing_comments, issue)
                .await?
            {
                fallback_issues.push(fallback);
            }
        }

        self.upsert_summary_comment(pr, gate_summary, &fallback_issues)
            .await
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

        let url = format!(
            "{}/repos/{}/{}/statuses/{}",
            self.api_base, self.owner, self.repo, sha
        );
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
        state
            .requests
            .lock()
            .unwrap()
            .push((format!("{owner}/{repo}/{sha}"), body, headers));
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
        assert_eq!(
            requests[0].1["description"].as_str().unwrap().len(),
            MAX_DESCRIPTION_LEN
        );
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
        // SAFETY: single-threaded test, no concurrent env access.
        unsafe {
            std::env::remove_var("GITHUB_TOKEN");
            std::env::remove_var("GITHUB_REPOSITORY");
        }
    }

    async fn serve_content(body: serde_json::Value) -> String {
        let app = Router::new().route(
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
        let content = reporter
            .fetch_file_content("src/main.rs", Some("abc123"))
            .await
            .unwrap();

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
        let err = reporter
            .fetch_file_content("src/main.rs", Some("abc123"))
            .await
            .unwrap_err();

        assert!(err.0.contains("unsupported"), "unexpected error: {}", err.0);
    }

    fn sample_issue(file: &str, line: u32) -> Issue {
        Issue::new(
            yunq_profiles::RuleId::new("test:rule").unwrap(),
            yunq_profiles::Severity::Major,
            "some message",
            file,
            yunq_ast::Span::new(line, 1, line, 10),
        )
    }

    #[derive(Clone, Default)]
    struct PrCaptured {
        review_posts: Arc<Mutex<Vec<serde_json::Value>>>,
        issue_posts: Arc<Mutex<Vec<serde_json::Value>>>,
    }

    #[derive(Clone, Default)]
    struct PrServerState {
        head_sha: String,
        review_pages: Arc<Vec<Vec<serde_json::Value>>>,
        issue_comments: Arc<Vec<serde_json::Value>>,
        captured: PrCaptured,
    }

    async fn get_pr(
        State(state): State<PrServerState>,
        Path((_owner, _repo, _num)): Path<(String, String, u32)>,
    ) -> Json<serde_json::Value> {
        Json(serde_json::json!({"head": {"sha": state.head_sha}}))
    }

    async fn get_review_comments(
        State(state): State<PrServerState>,
        Path((_owner, _repo, _num)): Path<(String, String, u32)>,
        axum::extract::Query(params): axum::extract::Query<
            std::collections::HashMap<String, String>,
        >,
    ) -> Json<serde_json::Value> {
        let page: usize = params.get("page").and_then(|p| p.parse().ok()).unwrap_or(1);
        let items = state
            .review_pages
            .get(page - 1)
            .cloned()
            .unwrap_or_default();
        Json(serde_json::Value::Array(items))
    }

    async fn post_review_comment(
        State(state): State<PrServerState>,
        Path((_owner, _repo, _num)): Path<(String, String, u32)>,
        Json(body): Json<serde_json::Value>,
    ) -> StatusCode {
        state.captured.review_posts.lock().unwrap().push(body);
        StatusCode::CREATED
    }

    async fn get_issue_comments(
        State(state): State<PrServerState>,
        Path((_owner, _repo, _num)): Path<(String, String, u32)>,
    ) -> Json<serde_json::Value> {
        Json(serde_json::Value::Array((*state.issue_comments).clone()))
    }

    async fn post_issue_comment(
        State(state): State<PrServerState>,
        Path((_owner, _repo, _num)): Path<(String, String, u32)>,
        Json(body): Json<serde_json::Value>,
    ) -> StatusCode {
        state.captured.issue_posts.lock().unwrap().push(body);
        StatusCode::CREATED
    }

    async fn start_pr_mock_server(
        head_sha: &str,
        review_pages: Vec<Vec<serde_json::Value>>,
        issue_comments: Vec<serde_json::Value>,
    ) -> (String, PrCaptured) {
        let state = PrServerState {
            head_sha: head_sha.to_string(),
            review_pages: Arc::new(review_pages),
            issue_comments: Arc::new(issue_comments),
            captured: PrCaptured::default(),
        };
        let captured = state.captured.clone();
        let app = Router::new()
            .route(
                "/repos/{owner}/{repo}/pulls/{num}",
                axum::routing::get(get_pr),
            )
            .route(
                "/repos/{owner}/{repo}/pulls/{num}/comments",
                axum::routing::get(get_review_comments).post(post_review_comment),
            )
            .route(
                "/repos/{owner}/{repo}/issues/{num}/comments",
                axum::routing::get(get_issue_comments).post(post_issue_comment),
            )
            .with_state(state);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (format!("http://{addr}"), captured)
    }

    #[tokio::test]
    async fn skips_issue_whose_existing_comment_position_went_stale() {
        // Simulates a comment posted on an earlier push: after a later
        // commit lands, GitHub nulls out `line` and only `original_line`
        // still says where it was. Dedup must still catch this or the same
        // issue gets reposted on every subsequent push.
        let existing = serde_json::json!({
            "path": "src/main.rs",
            "line": null,
            "original_line": 10,
            "body": "**test:rule**\nsome message",
        });
        let (base, captured) = start_pr_mock_server("headsha", vec![vec![existing]], vec![]).await;
        let reporter = GitHubStatusReporter::new("t", "acme", "widgets").with_api_base(base);

        let issue = sample_issue("src/main.rs", 10);
        reporter
            .report_pull_request_review(PullRequestNumber::new(7).unwrap(), &[issue], "gate passed")
            .await
            .unwrap();

        assert!(captured.review_posts.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn dedup_check_spans_every_page_of_existing_comments() {
        // A full first page (100 items) must not stop the fetch short —
        // the matching comment lives on page two.
        let filler: Vec<serde_json::Value> = (0..100)
            .map(|i| {
                serde_json::json!({
                    "path": "other.rs",
                    "line": i,
                    "original_line": null,
                    "body": "unrelated",
                })
            })
            .collect();
        let matching = serde_json::json!({
            "path": "src/main.rs",
            "line": 10,
            "original_line": null,
            "body": "**test:rule**\nsome message",
        });
        let (base, captured) =
            start_pr_mock_server("headsha", vec![filler, vec![matching]], vec![]).await;
        let reporter = GitHubStatusReporter::new("t", "acme", "widgets").with_api_base(base);

        let issue = sample_issue("src/main.rs", 10);
        reporter
            .report_pull_request_review(PullRequestNumber::new(7).unwrap(), &[issue], "gate passed")
            .await
            .unwrap();

        assert!(captured.review_posts.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn posts_new_review_comment_with_the_actual_pr_head_sha() {
        let (base, captured) = start_pr_mock_server("realheadsha123", vec![vec![]], vec![]).await;
        let reporter = GitHubStatusReporter::new("t", "acme", "widgets").with_api_base(base);

        let issue = sample_issue("src/main.rs", 10);
        reporter
            .report_pull_request_review(PullRequestNumber::new(7).unwrap(), &[issue], "gate passed")
            .await
            .unwrap();

        let posts = captured.review_posts.lock().unwrap();
        assert_eq!(posts.len(), 1);
        assert_eq!(posts[0]["commit_id"], "realheadsha123");
    }

    #[tokio::test]
    async fn fails_instead_of_treating_a_broken_fetch_as_no_existing_comments() {
        let app = Router::new()
            .route(
                "/repos/{owner}/{repo}/pulls/{num}",
                axum::routing::get(|| async {
                    Json(serde_json::json!({"head": {"sha": "headsha"}}))
                }),
            )
            .route(
                "/repos/{owner}/{repo}/pulls/{num}/comments",
                axum::routing::get(|| async { StatusCode::INTERNAL_SERVER_ERROR }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let base = format!("http://{addr}");

        let reporter = GitHubStatusReporter::new("t", "acme", "widgets").with_api_base(base);
        let issue = sample_issue("src/main.rs", 10);

        let err = reporter
            .report_pull_request_review(PullRequestNumber::new(7).unwrap(), &[issue], "gate passed")
            .await
            .unwrap_err();

        assert!(err.0.contains("500"), "unexpected error: {}", err.0);
    }
}
