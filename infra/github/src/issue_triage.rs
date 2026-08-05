//! Issue-side I/O for the Issue Triage Factory (roadmap C —
//! `docs/design/issue-triage-factory.md`). `core/triage::TriageLabel` is the
//! decision; this module is the one adapter that reads and writes it as an
//! actual GitHub issue label, and posts the runner's comments alongside it.
//!
//! Deliberately its own struct rather than more methods on
//! [`crate::GitHubStatusReporter`]: that type implements the multi-provider
//! `AlmGateway`/`AlmPullRequestReporter` ports (GitHub is one of four
//! adapters), while issue triage is GitHub-only for now — the design doc
//! never proposed widening those ports for it, so this stays a plain
//! GitHub-specific type instead of stretching a port that GitLab/Bitbucket/
//! Azure would also have to grow stub methods for.
//!
//! Every `triage:*` label this module writes must already exist as a
//! repository label — GitHub's "add labels" endpoint 404s on a name it
//! doesn't recognise rather than creating one on the fly, so provisioning
//! [`vord_triage::TriageLabel::ALL`] as repository labels is a one-time setup
//! step, not something this adapter can paper over per call.

use serde::{Deserialize, Serialize};
use vord_rules_engine::AlmError;
use vord_triage::TriageLabel;

const DEFAULT_API_BASE: &str = "https://api.github.com";

pub struct IssueTriageGateway {
    client: reqwest::Client,
    token: String,
    owner: String,
    repo: String,
    api_base: String,
}

impl IssueTriageGateway {
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

    /// Same environment `GitHubStatusReporter::from_env` reads, so a
    /// workflow that can report a status can drive issue triage with no
    /// extra setup.
    pub fn from_env() -> Option<Self> {
        let token = std::env::var("GITHUB_TOKEN").ok()?;
        let repository = std::env::var("GITHUB_REPOSITORY").ok()?;
        let (owner, repo) = repository.split_once('/')?;
        Some(Self::new(token, owner, repo).with_api_base(
            std::env::var("VORD_GITHUB_API_BASE").unwrap_or_else(|_| DEFAULT_API_BASE.to_string()),
        ))
    }

    pub fn with_api_base(mut self, base: impl Into<String>) -> Self {
        self.api_base = base.into();
        self
    }

    /// Attaches this gateway's auth headers to `request` and sends it,
    /// leaving what counts as success to the caller — `remove_label` treats
    /// a 404 as success, everything else does not. Every method below is a
    /// thin shell around this plus its own URL and success check; factored
    /// out once the fourth copy of the same boilerplate tripped vord's own
    /// `smells:duplicate-code` on this file.
    async fn send(&self, request: reqwest::RequestBuilder) -> Result<reqwest::Response, AlmError> {
        request
            .bearer_auth(&self.token)
            .header("Accept", "application/vnd.github+json")
            .header("User-Agent", "vord")
            .send()
            .await
            .map_err(|e| AlmError(e.to_string()))
    }

    /// Renders a failed response's status and body into the error every
    /// caller returns. Consumes `response` for its body, so callers check
    /// `status().is_success()` (which doesn't consume) before calling this.
    async fn error_for(response: reqwest::Response) -> AlmError {
        let status_code = response.status();
        let text = response.text().await.unwrap_or_default();
        AlmError(format!("GitHub returned {status_code}: {text}"))
    }

    /// Every label on `issue` this crate owns — filtered through
    /// [`TriageLabel::from_label`], so an issue's ordinary labels (`bug`,
    /// `good first issue`, ...) never reach the caller. More than one
    /// `triage:*` label on the same issue is a data problem the state
    /// machine was never meant to see happen, not something this method
    /// resolves on the caller's behalf.
    async fn triage_labels(&self, issue: u64) -> Result<Vec<TriageLabel>, AlmError> {
        let url = format!(
            "{}/repos/{}/{}/issues/{}/labels",
            self.api_base, self.owner, self.repo, issue
        );
        let response = self.send(self.client.get(&url)).await?;
        if !response.status().is_success() {
            return Err(Self::error_for(response).await);
        }
        let labels: Vec<LabelResponse> = response
            .json()
            .await
            .map_err(|e| AlmError(format!("failed to parse GitHub labels response: {e}")))?;
        Ok(labels
            .into_iter()
            .filter_map(|l| TriageLabel::from_label(&l.name))
            .collect())
    }

    /// The stage `issue` is currently labeled with, or `None` if the
    /// pipeline has never touched it (or a human removed its label).
    pub async fn current_label(&self, issue: u64) -> Result<Option<TriageLabel>, AlmError> {
        Ok(self.triage_labels(issue).await?.into_iter().next())
    }

    /// Moves `issue`'s label to `label`, removing whichever `triage:*`
    /// label it carried before. A no-op when `label` is already the issue's
    /// only triage label, so a caller can call this unconditionally after
    /// every `next_triage_state` without an extra existence check.
    pub async fn set_label(&self, issue: u64, label: TriageLabel) -> Result<(), AlmError> {
        let current = self.triage_labels(issue).await?;
        if current == [label] {
            return Ok(());
        }
        for stale in current.iter().copied().filter(|&l| l != label) {
            self.remove_label(issue, stale).await?;
        }
        if !current.contains(&label) {
            self.add_label(issue, label).await?;
        }
        Ok(())
    }

    async fn add_label(&self, issue: u64, label: TriageLabel) -> Result<(), AlmError> {
        let url = format!(
            "{}/repos/{}/{}/issues/{}/labels",
            self.api_base, self.owner, self.repo, issue
        );
        let body = AddLabelsRequest {
            labels: &[label.as_label()],
        };
        let response = self.send(self.client.post(&url).json(&body)).await?;
        if !response.status().is_success() {
            let status_code = response.status();
            let text = response.text().await.unwrap_or_default();
            return Err(AlmError(format!(
                "GitHub returned {status_code} adding label {:?} (does the repository label exist yet?): {text}",
                label.as_label()
            )));
        }
        Ok(())
    }

    async fn remove_label(&self, issue: u64, label: TriageLabel) -> Result<(), AlmError> {
        // GitHub's path-segment label name must be percent-encoded — every
        // label this crate writes contains `:`, which is a reserved
        // character in a URL path segment.
        let encoded = label.as_label().replace(':', "%3A");
        let url = format!(
            "{}/repos/{}/{}/issues/{}/labels/{}",
            self.api_base, self.owner, self.repo, issue, encoded
        );
        let response = self.send(self.client.delete(&url)).await?;
        // A label that is already gone (404, e.g. a human removed it
        // manually) is the state this call was trying to reach anyway.
        if !response.status().is_success() && response.status() != reqwest::StatusCode::NOT_FOUND {
            return Err(Self::error_for(response).await);
        }
        Ok(())
    }

    /// Posts one comment on `issue` — the runner's own progress narration
    /// (a diagnosis, a rejected fix attempt, a request for more info), not
    /// deduplicated against earlier comments the way the PR gate summary is.
    /// Each triage stage transition is a distinct event worth its own
    /// comment, not a single value to keep up to date in place.
    pub async fn post_comment(&self, issue: u64, body: &str) -> Result<(), AlmError> {
        let url = format!(
            "{}/repos/{}/{}/issues/{}/comments",
            self.api_base, self.owner, self.repo, issue
        );
        let req_body = CommentRequest { body };
        let response = self.send(self.client.post(&url).json(&req_body)).await?;
        if !response.status().is_success() {
            return Err(Self::error_for(response).await);
        }
        Ok(())
    }
}

#[derive(Deserialize)]
struct LabelResponse {
    name: String,
}

#[derive(Serialize)]
struct AddLabelsRequest<'a> {
    labels: &'a [&'a str],
}

#[derive(Serialize)]
struct CommentRequest<'a> {
    body: &'a str,
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use axum::extract::{Path, State};
    use axum::http::StatusCode;
    use axum::routing::{delete, get, post};
    use axum::{Json, Router};

    use super::*;

    #[derive(Clone, Default)]
    struct Captured {
        posts: Arc<Mutex<Vec<serde_json::Value>>>,
        deletes: Arc<Mutex<Vec<String>>>,
    }

    #[derive(Clone, Default)]
    struct ServerState {
        labels: Arc<Vec<serde_json::Value>>,
        captured: Captured,
    }

    async fn get_labels(
        State(state): State<ServerState>,
        Path((_owner, _repo, _issue)): Path<(String, String, u64)>,
    ) -> Json<serde_json::Value> {
        Json(serde_json::Value::Array((*state.labels).clone()))
    }

    async fn post_labels(
        State(state): State<ServerState>,
        Path((_owner, _repo, _issue)): Path<(String, String, u64)>,
        Json(body): Json<serde_json::Value>,
    ) -> StatusCode {
        state.captured.posts.lock().unwrap().push(body);
        StatusCode::OK
    }

    async fn delete_label(
        State(state): State<ServerState>,
        Path((_owner, _repo, _issue, name)): Path<(String, String, u64, String)>,
    ) -> StatusCode {
        state.captured.deletes.lock().unwrap().push(name);
        StatusCode::OK
    }

    async fn post_comment(
        State(state): State<ServerState>,
        Path((_owner, _repo, _issue)): Path<(String, String, u64)>,
        Json(body): Json<serde_json::Value>,
    ) -> StatusCode {
        state.captured.posts.lock().unwrap().push(body);
        StatusCode::CREATED
    }

    async fn start_mock_server(labels: Vec<serde_json::Value>) -> (String, Captured) {
        let state = ServerState {
            labels: Arc::new(labels),
            captured: Captured::default(),
        };
        let captured = state.captured.clone();
        let app = Router::new()
            .route(
                "/repos/{owner}/{repo}/issues/{issue}/labels",
                get(get_labels).post(post_labels),
            )
            .route(
                "/repos/{owner}/{repo}/issues/{issue}/labels/{name}",
                delete(delete_label),
            )
            .route(
                "/repos/{owner}/{repo}/issues/{issue}/comments",
                post(post_comment),
            )
            .with_state(state);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (format!("http://{addr}"), captured)
    }

    fn gateway(base: String) -> IssueTriageGateway {
        IssueTriageGateway::new("t", "acme", "widgets").with_api_base(base)
    }

    #[tokio::test]
    async fn current_label_is_none_when_the_issue_carries_no_triage_label() {
        let (base, _) = start_mock_server(vec![serde_json::json!({"name": "bug"})]).await;
        let label = gateway(base).current_label(7).await.unwrap();
        assert_eq!(label, None);
    }

    #[tokio::test]
    async fn current_label_finds_the_triage_label_among_ordinary_ones() {
        let (base, _) = start_mock_server(vec![
            serde_json::json!({"name": "bug"}),
            serde_json::json!({"name": "triage:diagnosing"}),
        ])
        .await;
        let label = gateway(base).current_label(7).await.unwrap();
        assert_eq!(label, Some(TriageLabel::Diagnosing));
    }

    #[tokio::test]
    async fn set_label_adds_the_target_when_none_is_present() {
        let (base, captured) = start_mock_server(vec![]).await;
        gateway(base).set_label(7, TriageLabel::New).await.unwrap();

        let posts = captured.posts.lock().unwrap();
        assert_eq!(posts.len(), 1);
        assert_eq!(posts[0]["labels"], serde_json::json!(["triage:new"]));
        assert!(captured.deletes.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn set_label_removes_the_stale_label_and_adds_the_new_one() {
        let (base, captured) =
            start_mock_server(vec![serde_json::json!({"name": "triage:reproducing"})]).await;
        gateway(base)
            .set_label(7, TriageLabel::Reproduced)
            .await
            .unwrap();

        // axum's Path extractor decodes the segment back for the handler —
        // seeing the bare name here (not `triage%3Areproducing`) confirms
        // the request itself carried the percent-encoded form on the wire.
        let deletes = captured.deletes.lock().unwrap();
        assert_eq!(deletes.as_slice(), ["triage:reproducing"]);
        let posts = captured.posts.lock().unwrap();
        assert_eq!(posts[0]["labels"], serde_json::json!(["triage:reproduced"]));
    }

    #[tokio::test]
    async fn set_label_is_a_noop_when_the_target_is_already_the_only_triage_label() {
        let (base, captured) =
            start_mock_server(vec![serde_json::json!({"name": "triage:fix-ready"})]).await;
        gateway(base)
            .set_label(7, TriageLabel::FixReady)
            .await
            .unwrap();

        assert!(captured.posts.lock().unwrap().is_empty());
        assert!(captured.deletes.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn post_comment_sends_the_body_as_is() {
        let (base, captured) = start_mock_server(vec![]).await;
        gateway(base)
            .post_comment(7, "diagnosis: null pointer on empty input")
            .await
            .unwrap();

        let posts = captured.posts.lock().unwrap();
        assert_eq!(posts[0]["body"], "diagnosis: null pointer on empty input");
    }

    #[tokio::test]
    async fn a_failed_label_fetch_is_an_error_not_an_empty_result() {
        let app = Router::new().route(
            "/repos/{owner}/{repo}/issues/{issue}/labels",
            get(|| async { StatusCode::INTERNAL_SERVER_ERROR }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let err = gateway(format!("http://{addr}"))
            .current_label(7)
            .await
            .unwrap_err();
        assert!(err.0.contains("500"), "unexpected error: {}", err.0);
    }

    #[test]
    fn from_env_parses_owner_repo() {
        // SAFETY: single-threaded test, no concurrent env access.
        unsafe {
            std::env::set_var("GITHUB_TOKEN", "tok");
            std::env::set_var("GITHUB_REPOSITORY", "acme/widgets");
        }
        let gateway = IssueTriageGateway::from_env().unwrap();
        assert_eq!(gateway.owner, "acme");
        assert_eq!(gateway.repo, "widgets");
        // SAFETY: single-threaded test, no concurrent env access.
        unsafe {
            std::env::remove_var("GITHUB_TOKEN");
            std::env::remove_var("GITHUB_REPOSITORY");
        }
    }
}
