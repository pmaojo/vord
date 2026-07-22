//! Outbound adapter: Azure DevOps Build Annotations & Statuses.

use reqwest::Client;
use serde::Serialize;
use yunq_rules_engine::{AlmError, AlmStatusReporter, CommitSha, CommitStatus, CommitStatusState};

#[derive(Clone)]
pub struct AzureDevOpsAdapter {
    client: Client,
    organization: String,
    project: String,
    pat: String,
}

impl AzureDevOpsAdapter {
    pub fn new(org: impl Into<String>, project: impl Into<String>, pat: impl Into<String>) -> Self {
        Self {
            client: Client::new(),
            organization: org.into(),
            project: project.into(),
            pat: pat.into(),
        }
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
    async fn report_commit_status(&self, sha: &CommitSha, status: &CommitStatus) -> Result<(), AlmError> {
        let state = match status.state {
            CommitStatusState::Success => "succeeded",
            CommitStatusState::Failure | CommitStatusState::Error => "failed",
            CommitStatusState::Pending => "pending",
        };
        let url = format!(
            "https://dev.azure.com/{}/{}/_apis/git/repositories/repo/commits/{}/statuses?api-version=7.0",
            self.organization, self.project, sha.as_str()
        );
        let payload = AzureStatusPayload {
            state,
            description: &status.description,
            context: AzureContext { name: &status.context, genre: "yunq" },
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
            Err(AlmError(format!("Azure DevOps returned status {status_code}: {body}")))
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
