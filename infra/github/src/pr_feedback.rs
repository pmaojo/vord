//! Reads late pull-request feedback for `yunq agent watch-pr` (roadmap A5):
//! review comments, issue comments, reviews and check runs, normalised into
//! `yunq_agent::feedback::FeedbackItem`.
//!
//! Every request is status-checked before its body is deserialised. This is
//! not defensive habit — GitHub delivers a rate-limit page, a 404 and a 500
//! on the same channel as data, and a body parsed without checking the status
//! deserialises `{"message": "API rate limit exceeded"}` into an empty list.
//! An empty list is [`Poll::observed`] with nothing in it, which the watch
//! reads as silence, which reports the pull request quiet. So: any failure on
//! any of the four calls turns the whole poll into
//! [`Poll::Unavailable`] — "we could not look", never "we looked and saw
//! nothing".

use serde::Deserialize;
use yunq_agent::feedback::{FeedbackItem, FeedbackSource, ItemVerdict, Poll};

const DEFAULT_API_BASE: &str = "https://api.github.com";

pub struct PullRequestFeedbackReader {
    client: reqwest::Client,
    token: String,
    owner: String,
    repo: String,
    api_base: String,
}

impl PullRequestFeedbackReader {
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

    /// Same environment `GitHubStatusReporter::from_env` reads, so a workflow
    /// that can report a status can watch a pull request with no extra setup.
    pub fn from_env() -> Option<Self> {
        let token = std::env::var("GITHUB_TOKEN").ok()?;
        let repository = std::env::var("GITHUB_REPOSITORY").ok()?;
        let (owner, repo) = repository.split_once('/')?;
        Some(Self::new(token, owner, repo).with_api_base(
            std::env::var("YUNQ_GITHUB_API_BASE").unwrap_or_else(|_| DEFAULT_API_BASE.to_string()),
        ))
    }

    pub fn with_api_base(mut self, base: impl Into<String>) -> Self {
        self.api_base = base.into();
        self
    }

    /// One poll: everything visible on the pull request right now.
    pub async fn poll(&self, number: u64) -> Poll {
        match self.collect(number).await {
            Ok(poll) => poll,
            Err(reason) => Poll::Unavailable(reason),
        }
    }

    async fn collect(&self, number: u64) -> Result<Poll, String> {
        let pull: PullRequest = self.get(&format!("pulls/{number}")).await?;
        let issue_comments: Vec<Comment> = self.get(&format!("issues/{number}/comments")).await?;
        let review_comments: Vec<Comment> = self.get(&format!("pulls/{number}/comments")).await?;
        let reviews: Vec<Review> = self.get(&format!("pulls/{number}/reviews")).await?;
        let checks: CheckRuns = self
            .get(&format!("commits/{}/check-runs", pull.head.sha))
            .await?;

        let mut items = Vec::new();
        items.extend(
            issue_comments
                .iter()
                .map(|c| c.to_item(FeedbackSource::IssueComment)),
        );
        items.extend(
            review_comments
                .iter()
                .map(|c| c.to_item(FeedbackSource::ReviewComment)),
        );
        items.extend(reviews.iter().filter_map(Review::to_item));
        items.extend(checks.check_runs.iter().filter_map(CheckRun::to_item));

        // A queued or running check has not reported yet. Counted rather than
        // guessed at: reporting it as clean would be a lie, reporting it as
        // failing would be a different one.
        let outstanding = checks
            .check_runs
            .iter()
            .filter(|run| !run.is_complete())
            .count();
        Ok(Poll::Observed { items, outstanding })
    }

    async fn get<T: for<'de> Deserialize<'de>>(&self, path: &str) -> Result<T, String> {
        let url = format!(
            "{}/repos/{}/{}/{path}",
            self.api_base, self.owner, self.repo
        );
        let response = self
            .client
            .get(&url)
            .bearer_auth(&self.token)
            .header("Accept", "application/vnd.github+json")
            .header("User-Agent", "yunq")
            .send()
            .await
            .map_err(|e| format!("GET {url} failed: {e}"))?;
        let status = response.status();
        let body = response
            .text()
            .await
            .map_err(|e| format!("GET {url} body unreadable: {e}"))?;
        if !status.is_success() {
            return Err(format!("GET {url} returned {status}: {body}"));
        }
        serde_json::from_str(&body).map_err(|e| format!("GET {url} sent unexpected JSON: {e}"))
    }
}

#[derive(Deserialize)]
struct PullRequest {
    head: Head,
}

#[derive(Deserialize)]
struct Head {
    sha: String,
}

#[derive(Deserialize)]
struct Actor {
    #[serde(default)]
    login: String,
    /// `"Bot"` for an app; absent on some webhook-shaped payloads, hence the
    /// login suffix fallback in [`Actor::is_bot`].
    #[serde(default, rename = "type")]
    kind: String,
}

impl Actor {
    fn is_bot(&self) -> bool {
        self.kind == "Bot" || self.login.ends_with("[bot]")
    }
}

#[derive(Deserialize)]
struct Comment {
    id: u64,
    #[serde(default)]
    body: String,
    #[serde(default)]
    user: Option<Actor>,
}

impl Comment {
    fn to_item(&self, source: FeedbackSource) -> FeedbackItem {
        let (author, bot) = actor_parts(self.user.as_ref());
        FeedbackItem {
            id: format!("comment:{}", self.id),
            source,
            author,
            body: truncate(&self.body),
            bot,
            verdict: ItemVerdict::Neutral,
        }
    }
}

#[derive(Deserialize)]
struct Review {
    id: u64,
    #[serde(default)]
    body: String,
    #[serde(default)]
    state: String,
    #[serde(default)]
    user: Option<Actor>,
}

impl Review {
    fn to_item(&self) -> Option<FeedbackItem> {
        // A review the author has not submitted yet is not feedback.
        if self.state.eq_ignore_ascii_case("PENDING") {
            return None;
        }
        let (author, bot) = actor_parts(self.user.as_ref());
        Some(FeedbackItem {
            id: format!("review:{}", self.id),
            source: FeedbackSource::Review,
            author,
            body: format!("{}: {}", self.state, truncate(&self.body)),
            bot,
            verdict: review_verdict(&self.state),
        })
    }
}

fn review_verdict(state: &str) -> ItemVerdict {
    match state.to_ascii_uppercase().as_str() {
        "APPROVED" => ItemVerdict::Clean,
        "CHANGES_REQUESTED" | "DISMISSED" => ItemVerdict::NeedsWork,
        _ => ItemVerdict::Neutral,
    }
}

#[derive(Deserialize)]
struct CheckRuns {
    #[serde(default)]
    check_runs: Vec<CheckRun>,
}

#[derive(Deserialize)]
struct CheckRun {
    id: u64,
    #[serde(default)]
    name: String,
    #[serde(default)]
    status: String,
    #[serde(default)]
    conclusion: Option<String>,
    #[serde(default)]
    app: Option<App>,
}

#[derive(Deserialize)]
struct App {
    #[serde(default)]
    slug: String,
}

impl CheckRun {
    fn is_complete(&self) -> bool {
        self.status.eq_ignore_ascii_case("completed")
    }

    fn to_item(&self) -> Option<FeedbackItem> {
        if !self.is_complete() {
            return None;
        }
        let conclusion = self.conclusion.clone().unwrap_or_default();
        Some(FeedbackItem {
            id: format!("check:{}:{conclusion}", self.id),
            source: FeedbackSource::CheckRun,
            author: self
                .app
                .as_ref()
                .map(|a| a.slug.clone())
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| self.name.clone()),
            body: format!("{} → {conclusion}", self.name),
            // A check run is always a machine, whatever posted it.
            bot: true,
            verdict: check_verdict(&conclusion),
        })
    }
}

fn check_verdict(conclusion: &str) -> ItemVerdict {
    match conclusion {
        "success" | "neutral" | "skipped" => ItemVerdict::Clean,
        "failure" | "timed_out" | "action_required" | "startup_failure" => ItemVerdict::NeedsWork,
        // `cancelled`, `stale` and anything GitHub adds later: not a pass and
        // not a failure. Neutral from a bot is non-actionable, which is right
        // — a cancelled run is a re-run away, not a defect.
        _ => ItemVerdict::Neutral,
    }
}

fn actor_parts(actor: Option<&Actor>) -> (String, bool) {
    match actor {
        Some(actor) => (actor.login.clone(), actor.is_bot()),
        // No author on the payload: treat it as human, so it is triaged
        // rather than silently folded into an all-clear.
        None => ("unknown".to_string(), false),
    }
}

/// Feedback bodies go into an agent's context; a 40KB CI log pasted into a
/// comment should not evict the transcript.
fn truncate(body: &str) -> String {
    const LIMIT: usize = 2000;
    if body.len() <= LIMIT {
        return body.to_string();
    }
    let mut cut = LIMIT;
    while !body.is_char_boundary(cut) {
        cut -= 1;
    }
    format!("{}… [truncated]", &body[..cut])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse<T: for<'de> Deserialize<'de>>(raw: &str) -> T {
        serde_json::from_str(raw).expect("valid fixture")
    }

    #[test]
    fn a_human_comment_becomes_an_actionable_neutral_item() {
        let comment: Comment =
            parse(r#"{"id":7,"body":"please rename this","user":{"login":"alice","type":"User"}}"#);
        let item = comment.to_item(FeedbackSource::IssueComment);
        assert_eq!(item.id, "comment:7");
        assert!(!item.bot);
        assert!(item.is_actionable());
    }

    #[test]
    fn a_bot_is_recognised_by_type_and_by_login_suffix() {
        let by_type: Comment =
            parse(r#"{"id":1,"body":"","user":{"login":"copilot","type":"Bot"}}"#);
        assert!(by_type.to_item(FeedbackSource::IssueComment).bot);
        let by_login: Comment = parse(r#"{"id":2,"body":"","user":{"login":"dependabot[bot]"}}"#);
        assert!(by_login.to_item(FeedbackSource::IssueComment).bot);
        let human: Comment = parse(r#"{"id":3,"body":"","user":{"login":"alice"}}"#);
        assert!(!human.to_item(FeedbackSource::IssueComment).bot);
    }

    #[test]
    fn a_comment_with_no_author_is_triaged_rather_than_treated_as_a_bot() {
        let comment: Comment = parse(r#"{"id":4,"body":"hi"}"#);
        let item = comment.to_item(FeedbackSource::IssueComment);
        assert!(!item.bot);
        assert!(item.is_actionable());
    }

    #[test]
    fn review_states_map_to_the_verdict_that_matches_them() {
        assert_eq!(review_verdict("APPROVED"), ItemVerdict::Clean);
        assert_eq!(review_verdict("CHANGES_REQUESTED"), ItemVerdict::NeedsWork);
        assert_eq!(review_verdict("COMMENTED"), ItemVerdict::Neutral);
        assert_eq!(
            review_verdict("approved"),
            ItemVerdict::Clean,
            "state casing varies by endpoint"
        );
    }

    #[test]
    fn a_pending_review_is_not_yet_feedback() {
        let review: Review =
            parse(r#"{"id":9,"state":"PENDING","body":"","user":{"login":"alice"}}"#);
        assert!(review.to_item().is_none());
    }

    #[test]
    fn a_submitted_review_carries_its_state_in_the_body() {
        let review: Review =
            parse(r#"{"id":9,"state":"CHANGES_REQUESTED","body":"nope","user":{"login":"alice"}}"#);
        let item = review.to_item().unwrap();
        assert_eq!(item.id, "review:9");
        assert!(item.body.contains("CHANGES_REQUESTED"));
        assert_eq!(item.verdict, ItemVerdict::NeedsWork);
    }

    #[test]
    fn check_conclusions_map_to_the_verdict_that_matches_them() {
        assert_eq!(check_verdict("success"), ItemVerdict::Clean);
        assert_eq!(check_verdict("skipped"), ItemVerdict::Clean);
        assert_eq!(check_verdict("failure"), ItemVerdict::NeedsWork);
        assert_eq!(check_verdict("timed_out"), ItemVerdict::NeedsWork);
        assert_eq!(check_verdict("cancelled"), ItemVerdict::Neutral);
        assert_eq!(check_verdict("something_new"), ItemVerdict::Neutral);
    }

    #[test]
    fn a_running_check_is_outstanding_rather_than_reported() {
        let run: CheckRun = parse(r#"{"id":1,"name":"CI","status":"in_progress"}"#);
        assert!(!run.is_complete());
        assert!(
            run.to_item().is_none(),
            "a check that has not finished has said nothing"
        );
    }

    #[test]
    fn a_completed_check_is_always_a_bot_and_keeps_its_conclusion_in_its_id() {
        let run: CheckRun = parse(
            r#"{"id":1,"name":"CI","status":"completed","conclusion":"failure","app":{"slug":"github-actions"}}"#,
        );
        let item = run.to_item().unwrap();
        assert!(item.bot);
        assert_eq!(item.author, "github-actions");
        // The conclusion is part of the identity so a re-run that flips from
        // failure to success reads as new feedback rather than as already
        // triaged.
        assert_eq!(item.id, "check:1:failure");
        assert!(item.is_actionable());
    }

    #[test]
    fn a_check_with_no_app_falls_back_to_its_own_name() {
        let run: CheckRun =
            parse(r#"{"id":1,"name":"lint","status":"completed","conclusion":"success"}"#);
        assert_eq!(run.to_item().unwrap().author, "lint");
    }

    #[test]
    fn an_enormous_body_is_truncated_on_a_character_boundary() {
        let body = "é".repeat(4000);
        let truncated = truncate(&body);
        assert!(truncated.ends_with("… [truncated]"));
        assert!(truncated.len() < body.len());
    }

    #[test]
    fn a_short_body_is_left_alone() {
        assert_eq!(truncate("fine"), "fine");
    }
}
