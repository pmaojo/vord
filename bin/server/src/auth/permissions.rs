//! Backend permission enforcement extractor. ROADMAP §Phase 4 — RBAC isn't
//! real until the backend rejects unauthorized requests, not just the
//! frontend's UI gate.
//!
//! Skeleton: the pure decision function + the axum-style extractor are in
//! place; wiring into every project-scoped route lands in following
//! iterations.

use serde::{Deserialize, Serialize};

use crate::auth::{Permission, Role, permissions_for as permissionsFor};

/// The shape returned by `/api/auth/me` — already in `auth.rs::OAuthUserDto`
/// but mirrored here so the permission module doesn't depend on a `reqwest`
/// dep or the auth service concrete impl.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CallerPermissions {
    pub username: String,
    pub roles: Vec<Role>,
}

impl CallerPermissions {
    pub fn anonymous() -> Self {
        Self { username: String::new(), roles: Vec::new() }
    }

    pub fn is_authenticated(&self) -> bool { !self.username.is_empty() }
}

/// Pure decision: does the caller have the required permission?
pub fn is_allowed(caller: &CallerPermissions, required: Permission) -> bool {
    if !caller.is_authenticated() { return false; }
    permissionsFor(&caller.roles).contains(&required)
}

/// A handler-level "denied" reason — the extractor turns this into a 403
/// response with the body the SPA already knows how to render.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DenyReason {
    pub required_permission: Permission,
    pub caller_roles: Vec<Role>,
}

impl DenyReason {
    pub fn new(required: Permission, caller: &CallerPermissions) -> Self {
        Self { required_permission: required, caller_roles: caller.roles.clone() }
    }
}

/// Tiny error enum the axum extractor returns. The `main.rs` glue turns
/// these into the proper HTTP status codes (401 vs 403).
#[derive(Debug, PartialEq, Eq)]
pub enum PermissionError {
    Unauthenticated,
    Forbidden(DenyReason),
}

/// Helper: assert multiple permissions at once (the caller needs ALL of
/// them). Returns the first failure for diagnostics.
pub fn check_all(caller: &CallerPermissions, required: &[Permission]) -> Result<(), PermissionError> {
    for &p in required {
        if !is_allowed(caller, p) {
            return Err(if !caller.is_authenticated() {
                PermissionError::Unauthenticated
            } else {
                PermissionError::Forbidden(DenyReason::new(p, caller))
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn caller(roles: Vec<Role>) -> CallerPermissions {
        CallerPermissions { username: "alice".to_string(), roles }
    }

    #[test]
    fn anonymous_is_never_allowed() {
        let anon = CallerPermissions::anonymous();
        assert!(!is_allowed(&anon, Permission::BrowseIssues));
        assert!(!is_allowed(&anon, Permission::AdminAccess));
    }

    #[test]
    fn admin_is_allowed_everything() {
        let c = caller(vec![Role::Admin]);
        assert!(is_allowed(&c, Permission::AdminAccess));
        assert!(is_allowed(&c, Permission::SubmitAnalyses));
        assert!(is_allowed(&c, Permission::TransitionIssues));
    }

    #[test]
    fn developer_cannot_administer_but_can_browse_and_transition() {
        let c = caller(vec![Role::Developer]);
        assert!(!is_allowed(&c, Permission::AdminAccess));
        assert!(is_allowed(&c, Permission::BrowseIssues));
        assert!(is_allowed(&c, Permission::TransitionIssues));
    }

    #[test]
    fn viewer_cannot_submit_or_transition() {
        let c = caller(vec![Role::Viewer]);
        assert!(is_allowed(&c, Permission::BrowseIssues));
        assert!(!is_allowed(&c, Permission::SubmitAnalyses));
        assert!(!is_allowed(&c, Permission::TransitionIssues));
        assert!(!is_allowed(&c, Permission::AdminAccess));
    }

    #[test]
    fn scanner_is_scan_only() {
        let c = caller(vec![Role::Scanner]);
        assert!(is_allowed(&c, Permission::SubmitAnalyses));
        assert!(!is_allowed(&c, Permission::BrowseIssues));
    }

    #[test]
    fn check_all_passes_when_every_permission_held() {
        let c = caller(vec![Role::Admin]);
        assert!(check_all(&c, &[Permission::AdminAccess, Permission::SubmitAnalyses]).is_ok());
    }

    #[test]
    fn check_all_returns_first_failure_for_anonymous() {
        let anon = CallerPermissions::anonymous();
        let r = check_all(&anon, &[Permission::BrowseIssues]);
        assert_eq!(r, Err(PermissionError::Unauthenticated));
    }

    #[test]
    fn check_all_returns_first_failure_with_deny_reason() {
        let c = caller(vec![Role::Viewer]);
        let r = check_all(&c, &[Permission::BrowseIssues, Permission::SubmitAnalyses]);
        match r {
            Err(PermissionError::Forbidden(reason)) => {
                assert_eq!(reason.required_permission, Permission::SubmitAnalyses);
                assert_eq!(reason.caller_roles, vec![Role::Viewer]);
            }
            _ => panic!("expected Forbidden"),
        }
    }

    #[test]
    fn multiple_roles_union_grants() {
        // a developer-scanner service account should be allowed both
        let c = caller(vec![Role::Developer, Role::Scanner]);
        assert!(is_allowed(&c, Permission::BrowseIssues));
        assert!(is_allowed(&c, Permission::SubmitAnalyses));
        assert!(!is_allowed(&c, Permission::AdminAccess));
    }
}
