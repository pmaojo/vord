//! Groups: collections of users that share a role bundle. ROADMAP §Phase 4
//! "Groups, global + per-project permissions, permission templates".
//!
//! Skeleton: types + membership logic are in place; storage + HTTP land
//! in following iterations.

use serde::{Deserialize, Serialize};

use crate::auth::users::LocalUser;

/// One group record. A group has a name and a set of members; per-project
/// grants are derived from `PermissionTemplate` instances assigned to the
/// group, not stored on the group itself.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Group {
    pub id: String,
    pub name: String,
    pub description: String,
    pub created_at: u64,
    pub member_user_ids: Vec<String>,
}

impl Group {
    pub fn new(id: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            description: String::new(),
            created_at: 0,
            member_user_ids: Vec::new(),
        }
    }

    pub fn add_member(&mut self, user_id: impl Into<String>) {
        let id = user_id.into();
        if !self.member_user_ids.contains(&id) {
            self.member_user_ids.push(id);
        }
    }

    pub fn remove_member(&mut self, user_id: &str) {
        self.member_user_ids.retain(|id| id != user_id);
    }

    pub fn is_member(&self, user_id: &str) -> bool {
        self.member_user_ids.iter().any(|id| id == user_id)
    }
}

/// A reusable permission bundle — apply-on-create pattern. New projects
/// matching `pattern` (e.g. `team-foo-*`) automatically inherit the role
/// grants of every group this template names.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PermissionTemplate {
    pub id: String,
    pub name: String,
    pub project_key_pattern: String,  // glob: "team-foo-*"
    pub group_grants: Vec<GroupGrant>,
}

/// One grant entry inside a template: "this group gets this role on
/// matching projects".
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupGrant {
    pub group_id: String,
    pub role: GroupRole,
}

/// Per-project role a group grants. Mirrors the fixed admin / editor /
/// viewer set today; Phase 7 widens to the full RBAC tier from
/// `auth::roles`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GroupRole {
    Admin,
    Editor,
    Viewer,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adding_then_removing_member_round_trips() {
        let mut g = Group::new("g1", "platform");
        g.add_member("alice");
        g.add_member("bob");
        g.add_member("alice");  // duplicate add is a no-op
        assert_eq!(g.member_user_ids, vec!["alice", "bob"]);
        g.remove_member("alice");
        assert_eq!(g.member_user_ids, vec!["bob"]);
        assert!(!g.is_member("alice"));
        assert!(g.is_member("bob"));
    }

    #[test]
    fn permission_template_carries_glob_pattern_and_grants() {
        let t = PermissionTemplate {
            id: "t1".to_string(),
            name: "team-foo default".to_string(),
            project_key_pattern: "team-foo-*".to_string(),
            group_grants: vec![
                GroupGrant { group_id: "g1".to_string(), role: GroupRole::Admin },
                GroupGrant { group_id: "g2".to_string(), role: GroupRole::Viewer },
            ],
        };
        assert_eq!(t.project_key_pattern, "team-foo-*");
        assert_eq!(t.group_grants.len(), 2);
        assert_eq!(t.group_grants[0].role, GroupRole::Admin);
    }

    #[test]
    fn group_role_serializes_snake_case() {
        assert_eq!(serde_json::to_string(&GroupRole::Admin).unwrap(), "\"admin\"");
        assert_eq!(serde_json::to_string(&GroupRole::Editor).unwrap(), "\"editor\"");
        assert_eq!(serde_json::to_string(&GroupRole::Viewer).unwrap(), "\"viewer\"");
    }

    #[test]
    fn group_new_starts_empty() {
        let g = Group::new("g", "engineers");
        assert!(g.member_user_ids.is_empty());
        assert!(g.description.is_empty());
    }

    #[test]
    fn _local_user_kept_for_compile_only() {
        // `_user` ensures the LocalUser type is in scope for future
        // expand-and-add-member tests; remove when the iteration lands.
        let _user: Option<LocalUser> = None;
    }
}
