//! Outbound adapter: post commit statuses & inline PR comments to Bitbucket API v2.

use reqwest::Client;
use serde::Serialize;
use yunq_rules_engine::{AlmError, AlmPullRequestReporter, AlmStatusReporter, CommitSha, CommitStatus, CommitStatusState, Issue, PullRequestNumber};

#[derive(Clone)]
pub struct BitbucketAdapter {
    client: Client,
    workspace: String,
    repo_slug: String,
    token: String,
}

impl BitbucketAdapter {
    pub fn new(workspace: impl Into<String>, repo_slug: impl Into<String>, token: impl Into<String>) -> Self {
        Self {
            client: Client::new(),
            workspace: workspace.into(),
            repo_slug: repo_slug.into(),
            token: token.into(),
        }
    }
}

#[derive(Serialize)]
struct BitbucketStatusPayload<'a> {
    state: &'a str,
    key: &'a str,
    description: &'a str,
}

impl AlmStatusReporter for BitbucketAdapter {
    async fn report_commit_status(&self, sha: &CommitSha, status: &CommitStatus) -> Result<(), AlmError> {
        let state = match status.state {
            CommitStatusState::Success => "SUCCESSFUL",
            CommitStatusState::Failure | CommitStatusState::Error => "FAILED",
            CommitStatusState::Pending => "INPROGRESS",
        };
        let url = format!(
            "https://api.bitbucket.org/2.0/repositories/{}/{}/commit/{}/statuses/build",
            self.workspace, self.repo_slug, sha.as_str()
        );
        let payload = BitbucketStatusPayload {
            state,
            description: &status.description,
            key: &status.context,
        };

        let resp = self
            .client
            .post(&url)
            .bearer_auth(&self.token)
            .json(&payload)
            .send()
            .await
            .map_err(|e| AlmError(e.to_string()))?;

        if resp.status().is_success() {
            Ok(())
        } else {
            let status_code = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            Err(AlmError(format!("Bitbucket returned status {status_code}: {body}")))
        }
    }
}

#[derive(Serialize)]
struct BitbucketCommentPayload<'a> {
    content: BitbucketCommentContent<'a>,
}

#[derive(Serialize)]
struct BitbucketCommentContent<'a> {
    raw: &'a str,
}

impl AlmPullRequestReporter for BitbucketAdapter {
    async fn report_pull_request_review(
        &self,
        pr_number: PullRequestNumber,
        new_issues: &[Issue],
        gate_summary: &str,
    ) -> Result<(), AlmError> {
        let mut content = String::from("## 🛡️ yunq MR Analysis Summary\n\n");
        content.push_str(&format!("**Quality Gate**: {}\n\n", gate_summary));

        if !new_issues.is_empty() {
            content.push_str(&format!("### New Issues ({})\n", new_issues.len()));
            for issue in new_issues {
                content.push_str(&format!("- [{:?}] `{}`: {} ({}:{})\n", issue.severity(), issue.rule().as_str(), issue.message(), issue.file(), issue.span().start_line));
            }
        }

        let url = format!(
            "https://api.bitbucket.org/2.0/repositories/{}/{}/pullrequests/{}/comments",
            self.workspace, self.repo_slug, pr_number.get()
        );

        let payload = BitbucketCommentPayload {
            content: BitbucketCommentContent { raw: &content },
        };

        let resp = self
            .client
            .post(&url)
            .bearer_auth(&self.token)
            .json(&payload)
            .send()
            .await
            .map_err(|e| AlmError(e.to_string()))?;

        if resp.status().is_success() {
            Ok(())
        } else {
            let status_code = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            Err(AlmError(format!("Bitbucket returned status {status_code}: {body}")))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn instantiates_adapter() {
        let adapter = BitbucketAdapter::new("my-workspace", "my-repo", "token123");
        assert_eq!(adapter.workspace, "my-workspace");
    }
}
