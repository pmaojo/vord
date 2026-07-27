//! Outbound adapter: per-project BYOK for the AI Remediation Agent. A
//! project without a row here uses the platform-wide default provider
//! (env-configured, see `yunq_infra_llm::LlmProviderConfig::from_env`);
//! a row overrides it with the project's own provider/model/API key.
//!
//! The API key is never persisted in plaintext. It's sealed with
//! AES-256-GCM under a server-side master key (`YUNQ_SECRETS_KEY`, 32
//! bytes, base64-encoded) before the INSERT, and only decrypted back in
//! memory when a caller actually needs to build the provider adapter — a
//! stolen database dump alone can't recover a tenant's key without also
//! having the process's environment.

use aes_gcm::aead::{Aead, AeadCore, KeyInit, OsRng};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use sqlx::Row;
use yunq_rules_engine::StorageError;

use crate::PgIssueStorage;

#[derive(Debug, thiserror::Error)]
pub enum LlmConfigError {
    #[error("storage error: {0}")]
    Storage(#[from] StorageError),
    #[error(
        "YUNQ_SECRETS_KEY is not set or invalid; per-project BYOK requires a 32-byte base64-encoded server-side secrets key: {0}"
    )]
    MissingSecretsKey(String),
    #[error("crypto error: {0}")]
    Crypto(String),
}

fn storage_err(e: impl std::fmt::Display) -> LlmConfigError {
    LlmConfigError::Storage(StorageError(e.to_string()))
}

/// A project's stored BYOK config, decrypted. `provider` is the wire string
/// (`"openai_compatible"` | `"anthropic"`) — kept as a plain string here so
/// this crate doesn't depend on `yunq-infra-llm`'s enum layout.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProjectLlmConfig {
    pub provider: String,
    pub base_url: Option<String>,
    pub model: String,
    pub api_key: String,
}

fn master_key() -> Result<Key<Aes256Gcm>, LlmConfigError> {
    let raw = std::env::var("YUNQ_SECRETS_KEY")
        .map_err(|_| LlmConfigError::MissingSecretsKey("YUNQ_SECRETS_KEY is unset".to_string()))?;
    let bytes = BASE64
        .decode(raw.trim())
        .map_err(|e| LlmConfigError::MissingSecretsKey(format!("not valid base64: {e}")))?;
    if bytes.len() != 32 {
        return Err(LlmConfigError::MissingSecretsKey(format!(
            "must decode to 32 bytes, got {}",
            bytes.len()
        )));
    }
    Ok(*Key::<Aes256Gcm>::from_slice(&bytes))
}

fn encrypt(key: &Key<Aes256Gcm>, plaintext: &str) -> Result<(Vec<u8>, Vec<u8>), LlmConfigError> {
    let cipher = Aes256Gcm::new(key);
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(&nonce, plaintext.as_bytes())
        .map_err(|e| LlmConfigError::Crypto(format!("encryption failed: {e}")))?;
    Ok((ciphertext, nonce.to_vec()))
}

fn decrypt(
    key: &Key<Aes256Gcm>,
    ciphertext: &[u8],
    nonce: &[u8],
) -> Result<String, LlmConfigError> {
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(nonce);
    let plaintext = cipher.decrypt(nonce, ciphertext).map_err(|e| {
        LlmConfigError::Crypto(format!(
            "decryption failed (wrong key or tampered ciphertext): {e}"
        ))
    })?;
    String::from_utf8(plaintext)
        .map_err(|e| LlmConfigError::Crypto(format!("decrypted plaintext wasn't valid UTF-8: {e}")))
}

impl PgIssueStorage {
    /// Upserts a project's BYOK provider config, encrypting `api_key`
    /// before it ever reaches the database. Creates the project by key on
    /// first sight, same as gate assignment and permission grants.
    pub async fn set_project_llm_config(
        &self,
        project_key: &str,
        provider: &str,
        base_url: Option<&str>,
        model: &str,
        api_key: &str,
    ) -> Result<(), LlmConfigError> {
        let key = master_key()?;
        let (cipher, nonce) = encrypt(&key, api_key)?;
        let project_id = self
            .ensure_project(project_key)
            .await
            .map_err(LlmConfigError::Storage)?;

        sqlx::query(
            "INSERT INTO project_llm_provider_config
                (project_id, provider, base_url, model, api_key_cipher, api_key_nonce, updated_at)
             VALUES ($1, $2, $3, $4, $5, $6, now())
             ON CONFLICT (project_id) DO UPDATE SET
                provider = EXCLUDED.provider,
                base_url = EXCLUDED.base_url,
                model = EXCLUDED.model,
                api_key_cipher = EXCLUDED.api_key_cipher,
                api_key_nonce = EXCLUDED.api_key_nonce,
                updated_at = now()",
        )
        .bind(project_id)
        .bind(provider)
        .bind(base_url)
        .bind(model)
        .bind(cipher)
        .bind(nonce)
        .execute(&self.pool)
        .await
        .map_err(storage_err)?;

        Ok(())
    }

    /// Reads a project's BYOK config, decrypting the API key. `Ok(None)`
    /// when the project has no override — callers fall back to the
    /// platform default.
    pub async fn get_project_llm_config(
        &self,
        project_key: &str,
    ) -> Result<Option<ProjectLlmConfig>, LlmConfigError> {
        let row = sqlx::query(
            "SELECT c.provider, c.base_url, c.model, c.api_key_cipher, c.api_key_nonce
             FROM project_llm_provider_config c
             JOIN projects p ON p.id = c.project_id
             WHERE p.key = $1",
        )
        .bind(project_key)
        .fetch_optional(&self.pool)
        .await
        .map_err(storage_err)?;

        let Some(row) = row else { return Ok(None) };

        let provider: String = row.try_get("provider").map_err(storage_err)?;
        let base_url: Option<String> = row.try_get("base_url").map_err(storage_err)?;
        let model: String = row.try_get("model").map_err(storage_err)?;
        let cipher: Vec<u8> = row.try_get("api_key_cipher").map_err(storage_err)?;
        let nonce: Vec<u8> = row.try_get("api_key_nonce").map_err(storage_err)?;

        let key = master_key()?;
        let api_key = decrypt(&key, &cipher, &nonce)?;

        Ok(Some(ProjectLlmConfig {
            provider,
            base_url,
            model,
            api_key,
        }))
    }

    /// Clears a project's BYOK override, reverting it to the platform
    /// default provider. Returns whether a row was actually removed.
    pub async fn delete_project_llm_config(
        &self,
        project_key: &str,
    ) -> Result<bool, LlmConfigError> {
        let result = sqlx::query(
            "DELETE FROM project_llm_provider_config
             WHERE project_id = (SELECT id FROM projects WHERE key = $1)",
        )
        .bind(project_key)
        .execute(&self.pool)
        .await
        .map_err(storage_err)?;

        Ok(result.rows_affected() > 0)
    }

    /// Resolves the project key that owns an issue, so the Remediation
    /// Agent can look up that project's BYOK config. `None` if the issue
    /// predates project scoping (`issues.project_id` NULL) or doesn't exist.
    pub async fn project_key_for_issue(
        &self,
        issue_id: i64,
    ) -> Result<Option<String>, StorageError> {
        sqlx::query(
            "SELECT p.key FROM issues i
             JOIN projects p ON p.id = i.project_id
             WHERE i.id = $1",
        )
        .bind(issue_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| StorageError(e.to_string()))?
        .map(|row| row.try_get::<String, _>("key"))
        .transpose()
        .map_err(|e| StorageError(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// `master_key` tests below mutate the process-wide `YUNQ_SECRETS_KEY`
    /// env var; serialize them so cargo's parallel test threads don't race.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn test_key() -> Key<Aes256Gcm> {
        *Key::<Aes256Gcm>::from_slice(&[7u8; 32])
    }

    #[test]
    fn encrypt_then_decrypt_round_trips() {
        let key = test_key();
        let (cipher, nonce) = encrypt(&key, "sk-super-secret").unwrap();
        let plaintext = decrypt(&key, &cipher, &nonce).unwrap();
        assert_eq!(plaintext, "sk-super-secret");
    }

    #[test]
    fn decrypt_fails_with_wrong_key() {
        let key = test_key();
        let other_key = *Key::<Aes256Gcm>::from_slice(&[9u8; 32]);
        let (cipher, nonce) = encrypt(&key, "sk-super-secret").unwrap();
        assert!(decrypt(&other_key, &cipher, &nonce).is_err());
    }

    #[test]
    fn decrypt_fails_on_tampered_ciphertext() {
        let key = test_key();
        let (mut cipher, nonce) = encrypt(&key, "sk-super-secret").unwrap();
        let last = cipher.len() - 1;
        cipher[last] ^= 0xFF;
        assert!(decrypt(&key, &cipher, &nonce).is_err());
    }

    #[test]
    fn encrypt_is_nondeterministic_across_calls() {
        // Distinct random nonces per call, standard AES-GCM hygiene: reusing
        // a nonce under the same key breaks the confidentiality guarantee.
        let key = test_key();
        let (cipher_a, nonce_a) = encrypt(&key, "same-plaintext").unwrap();
        let (cipher_b, nonce_b) = encrypt(&key, "same-plaintext").unwrap();
        assert_ne!(nonce_a, nonce_b);
        assert_ne!(cipher_a, cipher_b);
    }

    #[test]
    fn master_key_rejects_wrong_length() {
        let _guard = ENV_LOCK.lock().unwrap();
        // SAFETY: serialized by ENV_LOCK above.
        unsafe {
            std::env::set_var("YUNQ_SECRETS_KEY", BASE64.encode([1u8; 16]));
        }
        let err = master_key().unwrap_err();
        assert!(matches!(err, LlmConfigError::MissingSecretsKey(_)));
        unsafe {
            std::env::remove_var("YUNQ_SECRETS_KEY");
        }
    }

    #[test]
    fn master_key_accepts_32_bytes() {
        let _guard = ENV_LOCK.lock().unwrap();
        // SAFETY: serialized by ENV_LOCK above.
        unsafe {
            std::env::set_var("YUNQ_SECRETS_KEY", BASE64.encode([3u8; 32]));
        }
        assert!(master_key().is_ok());
        unsafe {
            std::env::remove_var("YUNQ_SECRETS_KEY");
        }
    }
}

#[cfg(test)]
mod live_db_tests {
    use super::*;

    async fn connected_storage() -> PgIssueStorage {
        let database_url = std::env::var("DATABASE_URL")
            .unwrap_or_else(|_| "postgres://yunq:yunq@localhost:5432/yunq".to_string());
        let storage = PgIssueStorage::connect_lazy(&database_url).unwrap();
        storage.migrate().await.unwrap();
        storage
    }

    fn unique_project_key(label: &str) -> String {
        format!(
            "llm-config-test-{label}-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        )
    }

    // SAFETY: `#[ignore]`d, only runs against a live Postgres one test at a
    // time via `cargo test -- --ignored --test-threads=1`; no parallel
    // access to YUNQ_SECRETS_KEY.
    fn set_test_secrets_key() {
        unsafe {
            std::env::set_var("YUNQ_SECRETS_KEY", BASE64.encode([5u8; 32]));
        }
    }

    #[tokio::test]
    #[ignore = "requires a live Postgres; see module docs"]
    async fn set_then_get_round_trips_decrypted_api_key() {
        set_test_secrets_key();
        let storage = connected_storage().await;
        let key = unique_project_key("round-trip");

        storage
            .set_project_llm_config(
                &key,
                "anthropic",
                None,
                "claude-sonnet-4-5-20250929",
                "sk-ant-test-key",
            )
            .await
            .unwrap();

        let config = storage
            .get_project_llm_config(&key)
            .await
            .unwrap()
            .expect("config was just set");
        assert_eq!(config.provider, "anthropic");
        assert_eq!(config.base_url, None);
        assert_eq!(config.model, "claude-sonnet-4-5-20250929");
        assert_eq!(config.api_key, "sk-ant-test-key");
    }

    #[tokio::test]
    #[ignore = "requires a live Postgres; see module docs"]
    async fn set_twice_upserts_rather_than_duplicating() {
        set_test_secrets_key();
        let storage = connected_storage().await;
        let key = unique_project_key("upsert");

        storage
            .set_project_llm_config(
                &key,
                "openai_compatible",
                Some("http://localhost:4000/v1"),
                "codellama",
                "key-1",
            )
            .await
            .unwrap();
        storage
            .set_project_llm_config(
                &key,
                "anthropic",
                None,
                "claude-sonnet-4-5-20250929",
                "key-2",
            )
            .await
            .unwrap();

        let config = storage.get_project_llm_config(&key).await.unwrap().unwrap();
        assert_eq!(config.provider, "anthropic");
        assert_eq!(config.api_key, "key-2");
    }

    #[tokio::test]
    #[ignore = "requires a live Postgres; see module docs"]
    async fn get_returns_none_for_a_project_without_an_override() {
        let storage = connected_storage().await;
        let key = unique_project_key("no-override");
        storage.ensure_project(&key).await.unwrap();

        assert_eq!(storage.get_project_llm_config(&key).await.unwrap(), None);
    }

    #[tokio::test]
    #[ignore = "requires a live Postgres; see module docs"]
    async fn delete_reverts_project_to_platform_default() {
        set_test_secrets_key();
        let storage = connected_storage().await;
        let key = unique_project_key("delete");
        storage
            .set_project_llm_config(&key, "anthropic", None, "model", "key")
            .await
            .unwrap();

        let deleted = storage.delete_project_llm_config(&key).await.unwrap();
        assert!(deleted);
        assert_eq!(storage.get_project_llm_config(&key).await.unwrap(), None);
    }

    #[tokio::test]
    #[ignore = "requires a live Postgres; see module docs"]
    async fn delete_is_false_when_no_override_existed() {
        let storage = connected_storage().await;
        let key = unique_project_key("delete-noop");
        storage.ensure_project(&key).await.unwrap();

        assert!(!storage.delete_project_llm_config(&key).await.unwrap());
    }

    #[tokio::test]
    #[ignore = "requires a live Postgres; see module docs"]
    async fn project_key_for_issue_resolves_the_owning_project() {
        let storage = connected_storage().await;
        let key = unique_project_key("issue-owner");
        let project_id = storage.ensure_project(&key).await.unwrap();

        let issue_id: i64 = sqlx::query(
            "INSERT INTO issues (rule, severity, message, file, start_line, start_col, end_line, end_col, status, project_id)
             VALUES ('test:rule', 'major', 'test', 'src/lib.rs', 1, 1, 1, 1, 'open', $1)
             RETURNING id",
        )
        .bind(project_id)
        .fetch_one(&storage.pool)
        .await
        .unwrap()
        .try_get("id")
        .unwrap();

        let resolved = storage.project_key_for_issue(issue_id).await.unwrap();
        assert_eq!(resolved.as_deref(), Some(key.as_str()));
    }

    #[tokio::test]
    #[ignore = "requires a live Postgres; see module docs"]
    async fn project_key_for_issue_is_none_when_project_id_is_null() {
        let storage = connected_storage().await;

        let issue_id: i64 = sqlx::query(
            "INSERT INTO issues (rule, severity, message, file, start_line, start_col, end_line, end_col, status, project_id)
             VALUES ('test:rule', 'major', 'test', 'src/lib.rs', 1, 1, 1, 1, 'open', NULL)
             RETURNING id",
        )
        .fetch_one(&storage.pool)
        .await
        .unwrap()
        .try_get("id")
        .unwrap();

        assert_eq!(storage.project_key_for_issue(issue_id).await.unwrap(), None);
    }
}
