/// A request to analyze a project checked out at a path reachable by a worker.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScanJob {
    project: String,
    path: String,
}

#[derive(Debug, thiserror::Error)]
#[error("scan job requires non-empty project and path")]
pub struct InvalidScanJobError;

impl ScanJob {
    pub fn new(
        project: impl Into<String>,
        path: impl Into<String>,
    ) -> Result<Self, InvalidScanJobError> {
        let project = project.into();
        let path = path.into();
        if project.trim().is_empty() || path.trim().is_empty() {
            return Err(InvalidScanJobError);
        }
        Ok(Self { project, path })
    }

    pub fn project(&self) -> &str {
        &self.project
    }

    pub fn path(&self) -> &str {
        &self.path
    }
}
