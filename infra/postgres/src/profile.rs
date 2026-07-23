//! Outbound adapter: quality profile persistence — named rule-activation
//! sets, structured the same way as `gate.rs`'s quality gates (a parent row
//! plus a child table of entries) rather than as an opaque JSON blob.

use sqlx::Row;
use yunq_rules_engine::{RuleId, Severity, StorageError};

use crate::PgIssueStorage;

fn storage_err(e: impl std::fmt::Display) -> StorageError {
    StorageError(e.to_string())
}

async fn profile_activations(
    tx: &mut sqlx::PgConnection,
    profile_id: i64,
) -> Result<Vec<(String, String)>, StorageError> {
    let rows = sqlx::query(
        "SELECT rule, severity FROM quality_profile_activations
         WHERE profile_id = $1 ORDER BY id",
    )
    .bind(profile_id)
    .fetch_all(tx)
    .await
    .map_err(storage_err)?;
    let mut activations = Vec::with_capacity(rows.len());
    for row in &rows {
        activations.push((
            row.try_get::<String, _>("rule").map_err(storage_err)?,
            row.try_get::<String, _>("severity").map_err(storage_err)?,
        ));
    }
    Ok(activations)
}

async fn replace_profile_activations(
    tx: &mut sqlx::PgConnection,
    profile_id: i64,
    activations: &[(RuleId, Severity)],
) -> Result<Vec<(String, String)>, StorageError> {
    sqlx::query("DELETE FROM quality_profile_activations WHERE profile_id = $1")
        .bind(profile_id)
        .execute(&mut *tx)
        .await
        .map_err(storage_err)?;

    let mut after = Vec::with_capacity(activations.len());
    for (rule, severity) in activations {
        sqlx::query(
            "INSERT INTO quality_profile_activations (profile_id, rule, severity)
             VALUES ($1, $2, $3)",
        )
        .bind(profile_id)
        .bind(rule.as_str())
        .bind(severity.as_str())
        .execute(&mut *tx)
        .await
        .map_err(storage_err)?;
        after.push((rule.as_str().to_string(), severity.as_str().to_string()));
    }
    Ok(after)
}

impl PgIssueStorage {
    /// Creates the named profile if it doesn't exist yet, then replaces its
    /// full set of rule activations — the write path behind
    /// `PUT /api/quality-profiles/{name}`. Returns `(before, after)`
    /// activation lists (rule id, severity) for the audit log; `before` is
    /// empty when the profile is new.
    pub async fn upsert_quality_profile(
        &self,
        name: &str,
        activations: &[(RuleId, Severity)],
    ) -> Result<(Vec<(String, String)>, Vec<(String, String)>), StorageError> {
        let mut tx = self.pool.begin().await.map_err(storage_err)?;

        let profile_id: i64 = sqlx::query(
            "INSERT INTO quality_profiles (name) VALUES ($1)
             ON CONFLICT (name) DO UPDATE SET name = EXCLUDED.name
             RETURNING id",
        )
        .bind(name)
        .fetch_one(&mut *tx)
        .await
        .map_err(storage_err)?
        .try_get("id")
        .map_err(storage_err)?;

        let before = profile_activations(&mut tx, profile_id).await?;
        let after = replace_profile_activations(&mut tx, profile_id, activations).await?;

        tx.commit().await.map_err(storage_err)?;
        Ok((before, after))
    }
}
