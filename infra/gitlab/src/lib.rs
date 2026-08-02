//! Outbound adapter: post commit statuses & inline MR comments to GitLab API v4.

use reqwest::Client;
use serde::Serialize;
use vord_rules_engine::{
    AlmError, AlmPullRequestReporter, AlmStatusReporter, AnalysisReport, CommitSha, CommitStatus,
    CommitStatusState, Issue, PullRequestNumber,
};

#[derive(Clone)]
pub struct GitLabAlmAdapter {
    client: Client,
    base_url: String,
    project_id: String,
    token: String,
}

impl GitLabAlmAdapter {
    pub fn new(
        base_url: impl Into<String>,
        project_id: impl Into<String>,
        token: impl Into<String>,
    ) -> Self {
        Self {
            client: Client::new(),
            base_url: base_url.into().trim_end_matches('/').to_string(),
            project_id: project_id.into(),
            token: token.into(),
        }
    }

    pub async fn post_mr_comment(&self, mr_id: u64, comment: &str) -> Result<(), AlmError> {
        let url = format!(
            "{}/api/v4/projects/{}/merge_requests/{}/notes",
            self.base_url, self.project_id, mr_id
        );
        let resp = self
            .client
            .post(&url)
            .header("PRIVATE-TOKEN", &self.token)
            .json(&serde_json::json!({ "body": comment }))
            .send()
            .await
            .map_err(|e| AlmError(e.to_string()))?;

        if resp.status().is_success() {
            Ok(())
        } else {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            Err(AlmError(format!("GitLab returned status {status}: {body}")))
        }
    }
}

#[derive(Serialize)]
struct GitLabStatusPayload<'a> {
    state: &'a str,
    context: &'a str,
    description: &'a str,
}

impl AlmStatusReporter for GitLabAlmAdapter {
    async fn report_commit_status(
        &self,
        sha: &CommitSha,
        status: &CommitStatus,
    ) -> Result<(), AlmError> {
        let state = match status.state {
            CommitStatusState::Success => "success",
            CommitStatusState::Failure | CommitStatusState::Error => "failed",
            CommitStatusState::Pending => "pending",
        };
        let url = format!(
            "{}/api/v4/projects/{}/statuses/{}",
            self.base_url,
            self.project_id,
            sha.as_str()
        );
        let payload = GitLabStatusPayload {
            state,
            context: &status.context,
            description: &status.description,
        };

        let resp = self
            .client
            .post(&url)
            .header("PRIVATE-TOKEN", &self.token)
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
                "GitLab returned status {status_code}: {body}"
            )))
        }
    }
}

impl AlmPullRequestReporter for GitLabAlmAdapter {
    async fn report_pull_request_review(
        &self,
        pr_number: PullRequestNumber,
        new_issues: &[Issue],
        gate_summary: &str,
    ) -> Result<(), AlmError> {
        let mut comment = String::from("## 🛡️ vord MR Analysis Summary\n\n");
        comment.push_str(&format!("**Quality Gate**: {}\n\n", gate_summary));

        if !new_issues.is_empty() {
            comment.push_str(&format!("### New Issues ({})\n", new_issues.len()));
            for issue in new_issues {
                comment.push_str(&format!(
                    "- [{:?}] `{}`: {} ({}:{})\n",
                    issue.severity(),
                    issue.rule().as_str(),
                    issue.message(),
                    issue.file(),
                    issue.span().start_line
                ));
            }
        }
        self.post_mr_comment(pr_number.get() as u64, &comment).await
    }
}

pub fn generate_mr_decoration_comment(report: &AnalysisReport) -> String {
    let mut comment = String::from("## 🛡️ vord Code Analysis Summary\n\n");
    comment.push_str(&format!("* **Issues Found**: {}\n", report.issues().len()));
    comment.push_str(&format!(
        "* **Security Hotspots**: {}\n\n",
        report.hotspots().len()
    ));

    if !report.issues().is_empty() {
        comment.push_str("### Issues\n");
        for issue in report.issues() {
            comment.push_str(&format!(
                "- [{:?}] `{}`: {} ({}:{})\n",
                issue.severity(),
                issue.rule().as_str(),
                issue.message(),
                issue.file(),
                issue.span().start_line
            ));
        }
    }
    comment
}

#[cfg(test)]
mod tests {
    use super::*;
    use vord_rules_engine::Metrics;

    #[test]
    fn generates_mr_comment() {
        let report = AnalysisReport::new(vec![], vec![], Metrics::default());
        let comment = generate_mr_decoration_comment(&report);
        assert!(comment.contains("vord Code Analysis Summary"));
    }
}
