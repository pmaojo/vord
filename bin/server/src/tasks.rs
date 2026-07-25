//! Background-task queue status API. ROADMAP §Phase 4 — "Background tasks:
//! task queue status API (SQS pipeline exists), per-project activity log,
//! failure diagnostics".
//!
//! Skeleton: the task status enum, the TaskStatusReport shape, and the
//! in-memory tracker are in place; the Postgres/SQS integration + HTTP
//! surface land in following iterations.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskState {
    Pending,
    Running,
    Succeeded,
    Failed,
    Retrying,
    Dead,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct TaskStatusReport {
    pub task_id: String,
    pub kind: String,                // "scan" | "remediation" | "webhook_delivery" | ...
    pub state: TaskState,
    pub submitted_at: u64,
    pub started_at: Option<u64>,
    pub finished_at: Option<u64>,
    pub attempts: u32,
    pub last_error: Option<String>,
    pub project_key: Option<String>,
    pub eta_seconds: Option<u64>,
}

/// In-memory tracker. Replaced by Postgres + LISTEN/NOTIFY adapter.
#[derive(Default)]
pub struct TaskTracker {
    tasks: HashMap<String, TaskStatusReport>,
}

impl TaskTracker {
    pub fn submit(&mut self, task_id: impl Into<String>, kind: impl Into<String>, submitted_at: u64) {
        self.tasks.insert(task_id.into(), TaskStatusReport {
            task_id: task_id.into(),
            kind: kind.into(),
            state: TaskState::Pending,
            submitted_at,
            started_at: None,
            finished_at: None,
            attempts: 0,
            last_error: None,
            project_key: None,
            eta_seconds: None,
        });
    }

    pub fn mark_running(&mut self, task_id: &str, started_at: u64) {
        if let Some(t) = self.tasks.get_mut(task_id) {
            t.state = TaskState::Running;
            t.started_at = Some(started_at);
            t.attempts += 1;
        }
    }

    pub fn mark_succeeded(&mut self, task_id: &str, finished_at: u64) {
        if let Some(t) = self.tasks.get_mut(task_id) {
            t.state = TaskState::Succeeded;
            t.finished_at = Some(finished_at);
            t.last_error = None;
        }
    }

    pub fn mark_failed(&mut self, task_id: &str, finished_at: u64, error: impl Into<String>, dead: bool) {
        if let Some(t) = self.tasks.get_mut(task_id) {
            t.state = if dead { TaskState::Dead } else { TaskState::Failed };
            t.finished_at = Some(finished_at);
            t.last_error = Some(error.into());
        }
    }

    pub fn get(&self, task_id: &str) -> Option<&TaskStatusReport> { self.tasks.get(task_id) }

    pub fn list_by_state(&self, state: TaskState) -> Vec<&TaskStatusReport> {
        self.tasks.values().filter(|t| t.state == state).collect()
    }

    pub fn depth(&self) -> usize {
        self.list_by_state(TaskState::Pending).len() + self.list_by_state(TaskState::Running).len() + self.list_by_state(TaskState::Retrying).len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lifecycle_pending_running_succeeded() {
        let mut t = TaskTracker::default();
        t.submit("t1", "scan", 1_000);
        t.mark_running("t1", 1_100);
        t.mark_succeeded("t1", 1_200);
        let task = t.get("t1").unwrap();
        assert_eq!(task.state, TaskState::Succeeded);
        assert_eq!(task.started_at, Some(1_100));
        assert_eq!(task.finished_at, Some(1_200));
        assert_eq!(task.attempts, 1);
        assert!(task.last_error.is_none());
    }

    #[test]
    fn failed_with_retry_still_running_depth() {
        let mut t = TaskTracker::default();
        t.submit("t1", "scan", 1_000);
        t.mark_running("t1", 1_100);
        t.mark_failed("t1", 1_200, "timeout", false);
        assert_eq!(t.depth(), 0); // failed tasks don't count toward queue depth
    }

    #[test]
    fn dead_task_is_terminal() {
        let mut t = TaskTracker::default();
        t.submit("t1", "scan", 1_000);
        t.mark_running("t1", 1_100);
        t.mark_failed("t1", 1_200, "boom", true);
        let task = t.get("t1").unwrap();
        assert_eq!(task.state, TaskState::Dead);
        assert_eq!(task.last_error.as_deref(), Some("boom"));
    }

    #[test]
    fn depth_counts_only_pending_running_retrying() {
        let mut t = TaskTracker::default();
        t.submit("p", "scan", 1_000);
        t.submit("r", "scan", 1_000);
        t.mark_running("r", 1_100);
        t.submit("s", "scan", 1_000);
        t.mark_running("s", 1_100);
        t.mark_succeeded("s", 1_200);
        assert_eq!(t.depth(), 2);
    }

    #[test]
    fn list_by_state_filters_correctly() {
        let mut t = TaskTracker::default();
        t.submit("a", "scan", 1_000);
        t.submit("b", "scan", 1_000);
        t.mark_running("b", 1_100);
        t.mark_succeeded("b", 1_200);
        let pending = t.list_by_state(TaskState::Pending);
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].task_id, "a");
    }

    #[test]
    fn mark_running_increments_attempts() {
        let mut t = TaskTracker::default();
        t.submit("t", "scan", 1_000);
        t.mark_running("t", 1_100);
        t.mark_running("t", 1_200);
        assert_eq!(t.get("t").unwrap().attempts, 2);
    }

    #[test]
    fn unknown_task_id_is_a_noop() {
        let mut t = TaskTracker::default();
        t.mark_running("missing", 1_000);  // must not panic
        t.mark_succeeded("missing", 1_100);
        assert!(t.get("missing").is_none());
    }
}
