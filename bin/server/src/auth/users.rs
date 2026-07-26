//! Local user accounts + personal access tokens + service account tokens.
//!
//! ROADMAP §Phase 4 — Auth: local users + user tokens (already-hashed at
//! rest), OAuth, SAML later. Service accounts with scoped tokens land in
//! Phase 7. This module is the bridge: the bearer auth path accepts both
//! OAuth sessions (existing) and PAT/service tokens (new).
//!
//! Skeleton: types and pure helpers are in place; the storage + HTTP layer
//! land in following iterations.

use serde::{Deserialize, Serialize};

/// Local user record. Passwords are never stored — only the Argon2id hash
/// with a per-user salt.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalUser {
    pub id: String,
    pub username: String,
    pub email: String,
    pub password_hash: String,  // argon2id $argon2id$v=19$...
    pub active: bool,
    pub created_at: u64,
}

/// A Personal Access Token — bearer-only, no UI login. Created by an
/// authenticated user from their account page; revocable at will.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersonalAccessToken {
    pub id: String,
    pub user_id: String,
    pub label: String,
    pub token_hash: String,  // sha256 of the raw token; raw never stored
    pub created_at: u64,
    pub expires_at: Option<u64>,
    pub revoked_at: Option<u64>,
    pub scopes: Vec<TokenScope>,
}

/// A service-account token (used by CI scanners / bots). Same shape as a
/// PAT but tied to a service user, not a person.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceToken {
    pub id: String,
    pub service_account: String,
    pub token_hash: String,
    pub created_at: u64,
    pub expires_at: Option<u64>,
    pub revoked_at: Option<u64>,
    pub scopes: Vec<TokenScope>,
}

/// The verbs a token can perform. Scopes are additive (a token with both
/// `ScanSubmit` and `IssuesRead` can do both). The HTTP layer rejects
/// requests whose required scope is missing from the bearer token.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TokenScope {
    ScanSubmit,
    IssuesRead,
    IssuesWrite,
    AdminRead,
    AdminWrite,
    WebhooksRead,
    WebhooksWrite,
}

impl TokenScope {
    /// All scopes — used by admin tokens to do anything. Kept explicit so
    /// adding a new scope forces a conscious decision about who has it.
    pub fn admin_set() -> &'static [TokenScope] {
        &[
            TokenScope::ScanSubmit,
            TokenScope::IssuesRead,
            TokenScope::IssuesWrite,
            TokenScope::AdminRead,
            TokenScope::AdminWrite,
            TokenScope::WebhooksRead,
            TokenScope::WebhooksWrite,
        ]
    }

    /// Scopes a freshly-issued PAT gets by default.
    pub fn default_pat() -> &'static [TokenScope] {
        &[TokenScope::ScanSubmit, TokenScope::IssuesRead]
    }

    /// Scopes a service account's CI token gets.
    pub fn default_service() -> &'static [TokenScope] {
        &[TokenScope::ScanSubmit]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admin_set_includes_every_scope() {
        let all = TokenScope::admin_set();
        assert!(all.contains(&TokenScope::ScanSubmit));
        assert!(all.contains(&TokenScope::AdminWrite));
        assert!(all.contains(&TokenScope::WebhooksWrite));
    }

    #[test]
    fn default_pat_scopes_are_user_safe() {
        let s = TokenScope::default_pat();
        assert!(s.contains(&TokenScope::ScanSubmit));
        assert!(s.contains(&TokenScope::IssuesRead));
        assert!(!s.contains(&TokenScope::AdminWrite));
        assert!(!s.contains(&TokenScope::WebhooksWrite));
    }

    #[test]
    fn default_service_token_is_scan_only() {
        let s = TokenScope::default_service();
        assert_eq!(s, &[TokenScope::ScanSubmit]);
    }

    #[test]
    fn local_user_carries_argon2id_hash_not_plaintext() {
        let u = LocalUser {
            id: "u1".to_string(),
            username: "alice".to_string(),
            email: "alice@example.com".to_string(),
            password_hash: "$argon2id$v=19$m=65536,t=2,p=1$...$...".to_string(),
            active: true,
            created_at: 1_700_000_000_000,
        };
        assert!(u.password_hash.starts_with("$argon2id$"));
        assert!(u.active);
    }

    #[test]
    fn personal_access_token_is_revocable() {
        let mut t = PersonalAccessToken {
            id: "t1".to_string(),
            user_id: "u1".to_string(),
            label: "laptop".to_string(),
            token_hash: "sha256:...".to_string(),
            created_at: 1_700_000_000_000,
            expires_at: None,
            revoked_at: None,
            scopes: TokenScope::default_pat().to_vec(),
        };
        assert!(t.revoked_at.is_none());
        t.revoked_at = Some(1_700_000_100_000);
        assert!(t.revoked_at.is_some());
    }

    #[test]
    fn service_token_can_be_optional_expiry() {
        let t = ServiceToken {
            id: "s1".to_string(),
            service_account: "ci-scanner".to_string(),
            token_hash: "sha256:...".to_string(),
            created_at: 1_700_000_000_000,
            expires_at: None,  // service tokens are typically non-expiring
            revoked_at: None,
            scopes: TokenScope::default_service().to_vec(),
        };
        assert!(t.expires_at.is_none());
        assert!(t.revoked_at.is_none());
    }

    #[test]
    fn scope_serializes_snake_case_for_jwt_and_db() {
        assert_eq!(serde_json::to_string(&TokenScope::ScanSubmit).unwrap(), "\"scan_submit\"");
        assert_eq!(serde_json::to_string(&TokenScope::AdminWrite).unwrap(), "\"admin_write\"");
    }
}
