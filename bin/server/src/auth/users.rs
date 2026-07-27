//! Local user accounts + personal access tokens + service account tokens.
//!
//! ROADMAP §Phase 4 — Auth: local users + user tokens (already-hashed at
//! rest), OAuth, SAML later. Service accounts with scoped tokens land in
//! Phase 7. This module is the bridge: the bearer auth path accepts both
//! OAuth sessions (existing) and PAT/service tokens (new).
//!
//! Skeleton: types and pure helpers are in place; the storage + HTTP layer
//! land in following iterations.

#![allow(dead_code)]

use std::collections::HashMap;
use std::sync::RwLock;

use futures::future::BoxFuture;
use serde::{Deserialize, Serialize};

use crate::auth::Role;
use crate::auth::permissions::CallerPermissions;

/// Local user record. Passwords are never stored — only the Argon2id hash
/// with a per-user salt.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalUser {
    pub id: String,
    pub username: String,
    pub email: String,
    pub password_hash: String, // argon2id $argon2id$v=19$...
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
    pub token_hash: String, // sha256 of the raw token; raw never stored
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

/// Errors returned by the user/token store. Kept intentionally small —
/// callers should not leak whether a username exists.
#[derive(Clone, Debug, thiserror::Error, PartialEq, Eq)]
pub enum UserStoreError {
    #[error("invalid credentials")]
    InvalidCredentials,
    #[error("user not found")]
    NotFound,
    #[error("duplicate username")]
    DuplicateUsername,
    #[error("token expired or revoked")]
    TokenRevoked,
    #[error("internal error")]
    Internal,
}

/// Storage port for local users and personal access tokens. Object-safe
/// (`BoxFuture`) so it can live behind `Arc<dyn UserStore>` in `AppState`.
pub trait UserStore: Send + Sync {
    /// Create a local user with a placeholder-hashed password. Production
    /// should replace the SHA-256 placeholder with Argon2id.
    fn create_user<'a>(
        &'a self,
        username: &'a str,
        email: &'a str,
        password: &'a str,
    ) -> BoxFuture<'a, Result<LocalUser, UserStoreError>>;

    /// Validate username + password and return the user record.
    fn authenticate_local<'a>(
        &'a self,
        username: &'a str,
        password: &'a str,
    ) -> BoxFuture<'a, Result<LocalUser, UserStoreError>>;

    /// Create a PAT for `user_id`. Returns the stored token record and the
    /// raw token (shown exactly once to the caller).
    fn create_pat<'a>(
        &'a self,
        user_id: &'a str,
        label: &'a str,
        scopes: Vec<TokenScope>,
    ) -> BoxFuture<'a, Result<(PersonalAccessToken, String), UserStoreError>>;

    /// Validate a bearer token (PAT) and return the caller it represents.
    fn authenticate_pat<'a>(
        &'a self,
        token: &'a str,
    ) -> BoxFuture<'a, Result<CallerPermissions, UserStoreError>>;

    /// Revoke a PAT. `user_id` ensures users can only revoke their own
    /// tokens (admins bypass via a separate path).
    fn revoke_pat<'a>(
        &'a self,
        user_id: &'a str,
        token_id: &'a str,
    ) -> BoxFuture<'a, Result<(), UserStoreError>>;

    /// List all PATs belonging to `user_id`.
    fn list_pats<'a>(
        &'a self,
        user_id: &'a str,
    ) -> BoxFuture<'a, Result<Vec<PersonalAccessToken>, UserStoreError>>;

    /// Look up a local user by username (case-insensitive).
    fn find_user_by_username<'a>(
        &'a self,
        username: &'a str,
    ) -> BoxFuture<'a, Result<LocalUser, UserStoreError>>;
}

/// In-memory implementation suitable for tests and the single-node CLI.
/// Data does not survive process restart.
pub struct InMemoryUserStore {
    users: RwLock<HashMap<String, LocalUser>>,
    users_by_username: RwLock<HashMap<String, String>>,
    pats: RwLock<HashMap<String, PersonalAccessToken>>,
    pats_by_hash: RwLock<HashMap<String, String>>,
}

impl InMemoryUserStore {
    pub fn new() -> Self {
        Self {
            users: RwLock::new(HashMap::new()),
            users_by_username: RwLock::new(HashMap::new()),
            pats: RwLock::new(HashMap::new()),
            pats_by_hash: RwLock::new(HashMap::new()),
        }
    }

    fn new_id() -> String {
        // Reuse the OAuth token generator — 16 bytes of entropy hex-encoded.
        super::random_token(16)
    }

    fn now() -> u64 {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64
    }

    fn hash_password(password: &str, salt: &str) -> String {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(password.as_bytes());
        hasher.update(salt.as_bytes());
        format!("sha256:{}:{:x}", salt, hasher.finalize())
    }

    fn verify_password(stored: &str, password: &str) -> bool {
        let parts: Vec<&str> = stored.splitn(3, ':').collect();
        if parts.len() != 3 || parts[0] != "sha256" {
            return false;
        }
        let salt = parts[1];
        Self::hash_password(password, salt) == stored
    }

    fn hash_token(token: &str) -> String {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(token.as_bytes());
        format!("sha256:{:x}", hasher.finalize())
    }

    fn roles_from_scopes(_scopes: &[TokenScope]) -> Vec<Role> {
        // PATs are scoped, but the existing route-level RBAC is role-based.
        // For now, any PAT maps to Developer; a future iteration can attach
        // explicit roles to users/tokens.
        vec![Role::Developer]
    }
}

impl Default for InMemoryUserStore {
    fn default() -> Self {
        Self::new()
    }
}

impl UserStore for InMemoryUserStore {
    fn create_user<'a>(
        &'a self,
        username: &'a str,
        email: &'a str,
        password: &'a str,
    ) -> BoxFuture<'a, Result<LocalUser, UserStoreError>> {
        Box::pin(async move {
            let lower = username.to_lowercase();
            {
                let by_username = self
                    .users_by_username
                    .read()
                    .unwrap_or_else(|p| p.into_inner());
                if by_username.contains_key(&lower) {
                    return Err(UserStoreError::DuplicateUsername);
                }
            }
            let id = Self::new_id();
            let salt = super::random_token(16);
            let user = LocalUser {
                id: id.clone(),
                username: username.to_string(),
                email: email.to_string(),
                password_hash: Self::hash_password(password, &salt),
                active: true,
                created_at: Self::now(),
            };
            {
                let mut users = self.users.write().unwrap_or_else(|p| p.into_inner());
                let mut by_username = self
                    .users_by_username
                    .write()
                    .unwrap_or_else(|p| p.into_inner());
                users.insert(id, user.clone());
                by_username.insert(lower, user.id.clone());
            }
            Ok(user)
        })
    }

    fn authenticate_local<'a>(
        &'a self,
        username: &'a str,
        password: &'a str,
    ) -> BoxFuture<'a, Result<LocalUser, UserStoreError>> {
        Box::pin(async move {
            let by_username = self
                .users_by_username
                .read()
                .unwrap_or_else(|p| p.into_inner());
            let user_id = by_username
                .get(&username.to_lowercase())
                .cloned()
                .ok_or(UserStoreError::InvalidCredentials)?;
            drop(by_username);

            let users = self.users.read().unwrap_or_else(|p| p.into_inner());
            let user = users
                .get(&user_id)
                .cloned()
                .ok_or(UserStoreError::Internal)?;
            drop(users);

            if !user.active || !Self::verify_password(&user.password_hash, password) {
                return Err(UserStoreError::InvalidCredentials);
            }
            Ok(user)
        })
    }

    fn create_pat<'a>(
        &'a self,
        user_id: &'a str,
        label: &'a str,
        scopes: Vec<TokenScope>,
    ) -> BoxFuture<'a, Result<(PersonalAccessToken, String), UserStoreError>> {
        Box::pin(async move {
            let users = self.users.read().unwrap_or_else(|p| p.into_inner());
            if !users.contains_key(user_id) {
                return Err(UserStoreError::NotFound);
            }
            drop(users);

            let raw = super::random_token(32);
            let token_hash = Self::hash_token(&raw);
            let pat = PersonalAccessToken {
                id: Self::new_id(),
                user_id: user_id.to_string(),
                label: label.to_string(),
                token_hash: token_hash.clone(),
                created_at: Self::now(),
                expires_at: None,
                revoked_at: None,
                scopes,
            };
            {
                let mut pats = self.pats.write().unwrap_or_else(|p| p.into_inner());
                let mut by_hash = self.pats_by_hash.write().unwrap_or_else(|p| p.into_inner());
                by_hash.insert(token_hash, pat.id.clone());
                pats.insert(pat.id.clone(), pat.clone());
            }
            Ok((pat, raw))
        })
    }

    fn authenticate_pat<'a>(
        &'a self,
        token: &'a str,
    ) -> BoxFuture<'a, Result<CallerPermissions, UserStoreError>> {
        Box::pin(async move {
            let token_hash = Self::hash_token(token);
            let pats = self.pats.read().unwrap_or_else(|p| p.into_inner());
            let token_id = pats_by_hash_lookup(&pats, &self.pats_by_hash, &token_hash)?;
            let pat = pats
                .get(&token_id)
                .cloned()
                .ok_or(UserStoreError::Internal)?;
            drop(pats);

            if pat.revoked_at.is_some() {
                return Err(UserStoreError::TokenRevoked);
            }
            if let Some(expires) = pat.expires_at {
                if Self::now() > expires {
                    return Err(UserStoreError::TokenRevoked);
                }
            }

            let users = self.users.read().unwrap_or_else(|p| p.into_inner());
            let user = users
                .get(&pat.user_id)
                .cloned()
                .ok_or(UserStoreError::Internal)?;
            drop(users);

            Ok(CallerPermissions {
                username: user.username,
                roles: Self::roles_from_scopes(&pat.scopes),
            })
        })
    }

    fn revoke_pat<'a>(
        &'a self,
        user_id: &'a str,
        token_id: &'a str,
    ) -> BoxFuture<'a, Result<(), UserStoreError>> {
        Box::pin(async move {
            let mut pats = self.pats.write().unwrap_or_else(|p| p.into_inner());
            let pat = pats.get_mut(token_id).ok_or(UserStoreError::NotFound)?;
            if pat.user_id != user_id {
                return Err(UserStoreError::NotFound);
            }
            pat.revoked_at = Some(Self::now());
            Ok(())
        })
    }

    fn list_pats<'a>(
        &'a self,
        user_id: &'a str,
    ) -> BoxFuture<'a, Result<Vec<PersonalAccessToken>, UserStoreError>> {
        Box::pin(async move {
            let pats = self.pats.read().unwrap_or_else(|p| p.into_inner());
            let mut owned: Vec<PersonalAccessToken> = pats
                .values()
                .filter(|pat| pat.user_id == user_id)
                .cloned()
                .collect();
            drop(pats);
            owned.sort_by_key(|pat| std::cmp::Reverse(pat.created_at));
            Ok(owned)
        })
    }

    fn find_user_by_username<'a>(
        &'a self,
        username: &'a str,
    ) -> BoxFuture<'a, Result<LocalUser, UserStoreError>> {
        Box::pin(async move {
            let by_username = self
                .users_by_username
                .read()
                .unwrap_or_else(|p| p.into_inner());
            let user_id = by_username
                .get(&username.to_lowercase())
                .cloned()
                .ok_or(UserStoreError::NotFound)?;
            drop(by_username);

            let users = self.users.read().unwrap_or_else(|p| p.into_inner());
            users.get(&user_id).cloned().ok_or(UserStoreError::Internal)
        })
    }
}

fn pats_by_hash_lookup(
    _pats: &HashMap<String, PersonalAccessToken>,
    pats_by_hash: &RwLock<HashMap<String, String>>,
    token_hash: &str,
) -> Result<String, UserStoreError> {
    let by_hash = pats_by_hash.read().unwrap_or_else(|p| p.into_inner());
    by_hash
        .get(token_hash)
        .cloned()
        .ok_or(UserStoreError::InvalidCredentials)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn user_store_round_trip() {
        let store = InMemoryUserStore::new();
        let user = store
            .create_user("alice", "alice@example.com", "password123")
            .await
            .unwrap();
        assert_eq!(user.username, "alice");
        assert!(user.password_hash.starts_with("sha256:"));

        let auth = store
            .authenticate_local("alice", "password123")
            .await
            .unwrap();
        assert_eq!(auth.username, "alice");

        let wrong = store.authenticate_local("alice", "wrong").await;
        assert_eq!(wrong, Err(UserStoreError::InvalidCredentials));
    }

    #[tokio::test]
    async fn duplicate_username_is_rejected() {
        let store = InMemoryUserStore::new();
        store
            .create_user("alice", "a@example.com", "password123")
            .await
            .unwrap();
        let result = store
            .create_user("alice", "b@example.com", "password123")
            .await;
        assert_eq!(result, Err(UserStoreError::DuplicateUsername));
    }

    #[tokio::test]
    async fn pat_authenticates_and_revokes() {
        let store = InMemoryUserStore::new();
        let user = store
            .create_user("bob", "bob@example.com", "password123")
            .await
            .unwrap();
        let (pat, raw) = store
            .create_pat(&user.id, "laptop", TokenScope::default_pat().to_vec())
            .await
            .unwrap();
        assert!(pat.token_hash.starts_with("sha256:"));

        let caller = store.authenticate_pat(&raw).await.unwrap();
        assert_eq!(caller.username, "bob");
        assert!(caller.roles.contains(&Role::Developer));

        store.revoke_pat(&user.id, &pat.id).await.unwrap();
        let revoked = store.authenticate_pat(&raw).await;
        assert_eq!(revoked, Err(UserStoreError::TokenRevoked));
    }

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
            expires_at: None, // service tokens are typically non-expiring
            revoked_at: None,
            scopes: TokenScope::default_service().to_vec(),
        };
        assert!(t.expires_at.is_none());
        assert!(t.revoked_at.is_none());
    }

    #[test]
    fn scope_serializes_snake_case_for_jwt_and_db() {
        assert_eq!(
            serde_json::to_string(&TokenScope::ScanSubmit).unwrap(),
            "\"scan_submit\""
        );
        assert_eq!(
            serde_json::to_string(&TokenScope::AdminWrite).unwrap(),
            "\"admin_write\""
        );
    }
}
