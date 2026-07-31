//! Outbound adapter: Azure DevOps Build Annotations & Statuses.

use reqwest::Client;
use serde::Serialize;
use yunq_rules_engine::{
    AlmError, AlmPullRequestReporter, AlmStatusReporter, CommitSha, CommitStatus,
    CommitStatusState, Issue, PullRequestNumber,
};

#[derive(Clone)]
pub struct AzureDevOpsAdapter {
    client: Client,
    organization: String,
    project: String,
    repository: String,
    pat: String,
}

impl AzureDevOpsAdapter {
    pub fn new(org: impl Into<String>, project: impl Into<String>, pat: impl Into<String>) -> Self {
        Self {
            client: Client::new(),
            organization: org.into(),
            project: project.into(),
            repository: "repo".into(),
            pat: pat.into(),
        }
    }

    pub fn with_repository(mut self, repository: impl Into<String>) -> Self {
        self.repository = repository.into();
        self
    }
}

#[derive(Serialize)]
struct AzureStatusPayload<'a> {
    state: &'a str,
    description: &'a str,
    context: AzureContext<'a>,
}

#[derive(Serialize)]
struct AzureContext<'a> {
    name: &'a str,
    genre: &'a str,
}

impl AlmStatusReporter for AzureDevOpsAdapter {
    async fn report_commit_status(
        &self,
        sha: &CommitSha,
        status: &CommitStatus,
    ) -> Result<(), AlmError> {
        let state = match status.state {
            CommitStatusState::Success => "succeeded",
            CommitStatusState::Failure | CommitStatusState::Error => "failed",
            CommitStatusState::Pending => "pending",
        };
        let url = format!(
            "https://dev.azure.com/{}/{}/_apis/git/repositories/{}/commits/{}/statuses?api-version=7.0",
            self.organization,
            self.project,
            self.repository,
            sha.as_str()
        );
        let payload = AzureStatusPayload {
            state,
            description: &status.description,
            context: AzureContext {
                name: &status.context,
                genre: "yunq",
            },
        };

        let resp = self
            .client
            .post(&url)
            .basic_auth("", Some(&self.pat))
            .json(&payload)
            .send()
            .await
            .map_err(|e| AlmError(e.to_string()))?;

        if resp.status().is_success() {
            Ok(())
        } else {
            let status_code = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            Err(AlmError(format!(
                "Azure DevOps returned status {status_code}: {body}"
            )))
        }
    }
}

#[derive(Serialize)]
struct AzureThreadPayload<'a> {
    comments: Vec<AzureCommentPayload<'a>>,
    status: u8,
}

#[derive(Serialize)]
struct AzureCommentPayload<'a> {
    #[serde(rename = "parentCommentId")]
    parent_comment_id: u8,
    content: &'a str,
    #[serde(rename = "commentType")]
    comment_type: u8,
}

impl AlmPullRequestReporter for AzureDevOpsAdapter {
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
                content.push_str(&format!(
                    "- [{:?}] `{}`: {} ({}:{})\n",
                    issue.severity(),
                    issue.rule().as_str(),
                    issue.message(),
                    issue.file(),
                    issue.span().start_line
                ));
            }
        }

        let url = format!(
            "https://dev.azure.com/{}/{}/_apis/git/repositories/{}/pullRequests/{}/threads?api-version=7.0",
            self.organization,
            self.project,
            self.repository,
            pr_number.get()
        );

        let payload = AzureThreadPayload {
            comments: vec![AzureCommentPayload {
                parent_comment_id: 0,
                content: &content,
                comment_type: 1, // text
            }],
            status: 1, // active
        };

        let resp = self
            .client
            .post(&url)
            .basic_auth("", Some(&self.pat))
            .json(&payload)
            .send()
            .await
            .map_err(|e| AlmError(e.to_string()))?;

        if resp.status().is_success() {
            Ok(())
        } else {
            let status_code = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            Err(AlmError(format!(
                "Azure DevOps returned status {status_code}: {body}"
            )))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn instantiates_adapter() {
        let adapter = AzureDevOpsAdapter::new("my-org", "my-project", "pat123");
        assert_eq!(adapter.organization, "my-org");
    }
}
