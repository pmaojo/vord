//! Outbound adapter: quality profile persistence — named rule-activation
//! sets, structured the same way as `gate.rs`'s quality gates (a parent row
//! plus a child table of entries) rather than as an opaque JSON blob.
//!
//! Also the thin persistence layer behind issue #22's compare/copy/
//! backup-restore operations: [`PgConfigStore::read_quality_profile`]
//! rebuilds a `QualityProfile` (parent chain included, via `parent_id` —
//! see migration `0018_quality_profile_inheritance.sql`) from stored rows,
//! and [`PgConfigStore::compare_quality_profiles`],
//! [`PgConfigStore::copy_quality_profile`] and
//! [`PgConfigStore::restore_quality_profile`] each read what they need
//! through it and hand off to the pure `core/profiles` functions
//! (`compare`, `copy_profile`, `restore`) for the actual decision —
//! this file only does I/O.

use sqlx::Row;
use yunq_rules_engine::{
    ProfileBackup, ProfileDiff, QualityProfile, RestorePolicy, RuleId, Severity, StorageError,
};

use crate::PgConfigStore;

fn storage_err(e: impl std::fmt::Display) -> StorageError {
    StorageError(e.to_string())
}

/// A parent chain shouldn't be able to cycle back on itself through this
/// crate's own writes (`restore_quality_profile` is the only path that
/// sets `parent_id`, and it always points at an already-existing row), but
/// this is a defensive bound all the same — without it, a cycle would spin
/// [`PgConfigStore::read_quality_profile`] forever instead of returning a
/// clear error.
const MAX_PARENT_CHAIN_DEPTH: u8 = 16;

/// A profile named `name` was not found in this database.
#[derive(Debug, thiserror::Error)]
#[error("no quality profile named {0:?}")]
pub struct ProfileNotFoundError(pub String);

/// Errors from comparing two stored profiles.
#[derive(Debug, thiserror::Error)]
pub enum CompareProfileError {
    #[error(transparent)]
    NotFound(#[from] ProfileNotFoundError),
    #[error(transparent)]
    Storage(#[from] StorageError),
}

/// Errors from copying a stored profile.
#[derive(Debug, thiserror::Error)]
pub enum CopyProfileError {
    #[error(transparent)]
    NotFound(#[from] ProfileNotFoundError),
    #[error(transparent)]
    Storage(#[from] StorageError),
}

/// Errors from restoring a profile backup.
#[derive(Debug, thiserror::Error)]
pub enum RestoreProfileError {
    /// A profile with the backup's name already exists and the caller
    /// didn't force an overwrite — see `yunq_profiles::RestorePolicy`.
    #[error(transparent)]
    Conflict(#[from] yunq_rules_engine::RestoreError),
    #[error(transparent)]
    Storage(#[from] StorageError),
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

impl PgConfigStore {
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

    /// Row lookup by name: `(id, parent_id)`, or `None` if no profile has
    /// that name.
    async fn profile_row_by_name(
        &self,
        name: &str,
    ) -> Result<Option<(i64, Option<i64>)>, StorageError> {
        let row = sqlx::query("SELECT id, parent_id FROM quality_profiles WHERE name = $1")
            .bind(name)
            .fetch_optional(&self.pool)
            .await
            .map_err(storage_err)?;
        let Some(row) = row else { return Ok(None) };
        Ok(Some((
            row.try_get::<i64, _>("id").map_err(storage_err)?,
            row.try_get::<Option<i64>, _>("parent_id")
                .map_err(storage_err)?,
        )))
    }

    async fn profile_name_by_id(&self, id: i64) -> Result<Option<String>, StorageError> {
        let row = sqlx::query("SELECT name FROM quality_profiles WHERE id = $1")
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .map_err(storage_err)?;
        row.map(|row| row.try_get::<String, _>("name").map_err(storage_err))
            .transpose()
    }

    async fn own_activations_typed(
        &self,
        profile_id: i64,
    ) -> Result<Vec<(RuleId, Severity)>, StorageError> {
        let raw = {
            let mut conn = self.pool.acquire().await.map_err(storage_err)?;
            profile_activations(&mut conn, profile_id).await?
        };
        raw.into_iter()
            .map(|(rule, severity)| {
                let rule = RuleId::new(&rule).map_err(storage_err)?;
                let severity = Severity::parse(&severity)
                    .ok_or_else(|| StorageError(format!("invalid stored severity {severity:?}")))?;
                Ok((rule, severity))
            })
            .collect()
    }

    /// Rebuilds a `QualityProfile` named `name` from its stored rows,
    /// following `parent_id` up the chain (own activations override
    /// inherited ones, same as `QualityProfile::with_parent` — this just
    /// reconstructs what was persisted). Returns `Ok(None)` if no profile
    /// has that name; `Err` only on a storage/data problem (including a
    /// parent chain deeper than [`MAX_PARENT_CHAIN_DEPTH`], which would
    /// otherwise mean a cycle).
    pub async fn read_quality_profile(
        &self,
        name: &str,
    ) -> Result<Option<QualityProfile>, StorageError> {
        // Collect the chain leaf-to-root as (name, activations) pairs, then
        // fold root-to-leaf into nested `QualityProfile`s — building it the
        // other way round would need recursion through an async fn, which
        // needs boxing for the recursive future; a plain loop avoids that.
        let mut chain: Vec<(String, Vec<(RuleId, Severity)>)> = Vec::new();
        let mut current_name = name.to_string();
        for depth in 0..=MAX_PARENT_CHAIN_DEPTH {
            if depth == MAX_PARENT_CHAIN_DEPTH {
                return Err(StorageError(format!(
                    "quality profile {name:?} parent chain exceeds {MAX_PARENT_CHAIN_DEPTH} levels (cycle?)"
                )));
            }
            let Some((id, parent_id)) = self.profile_row_by_name(&current_name).await? else {
                if chain.is_empty() {
                    return Ok(None);
                }
                // A parent_id pointed at a row that's since been deleted
                // (ON DELETE SET NULL should prevent this, but don't hang
                // if it ever happens): treat the chain as ending here.
                break;
            };
            let activations = self.own_activations_typed(id).await?;
            chain.push((current_name.clone(), activations));
            match parent_id {
                Some(parent_id) => match self.profile_name_by_id(parent_id).await? {
                    Some(parent_name) => current_name = parent_name,
                    None => break,
                },
                None => break,
            }
        }

        let mut iter = chain.into_iter().rev();
        let (root_name, root_activations) = iter
            .next()
            .expect("chain has at least one entry when a profile was found");
        let mut profile = QualityProfile::from_activations(root_name, root_activations);
        for (name, activations) in iter {
            profile = QualityProfile::from_activations(name, activations).with_parent(profile);
        }
        Ok(Some(profile))
    }

    /// Compares two stored profiles' effective (inheritance-resolved)
    /// activations — issue #22's "Compare profiles" operation. Read-only.
    pub async fn compare_quality_profiles(
        &self,
        name_a: &str,
        name_b: &str,
    ) -> Result<ProfileDiff, CompareProfileError> {
        let profile_a = self
            .read_quality_profile(name_a)
            .await?
            .ok_or_else(|| ProfileNotFoundError(name_a.to_string()))?;
        let profile_b = self
            .read_quality_profile(name_b)
            .await?
            .ok_or_else(|| ProfileNotFoundError(name_b.to_string()))?;
        Ok(yunq_rules_engine::compare(&profile_a, &profile_b))
    }

    /// Duplicates `source_name`'s effective activations under `new_name` —
    /// issue #22's "Copy profile" operation. The copy is a standalone
    /// snapshot (no parent link), per `yunq_profiles::copy_profile`'s
    /// semantics. Returns the copy's activations for the audit log, same
    /// shape as `upsert_quality_profile`'s `after`.
    pub async fn copy_quality_profile(
        &self,
        source_name: &str,
        new_name: &str,
    ) -> Result<Vec<(String, String)>, CopyProfileError> {
        let source = self
            .read_quality_profile(source_name)
            .await?
            .ok_or_else(|| ProfileNotFoundError(source_name.to_string()))?;
        let copy = yunq_rules_engine::copy_profile(&source, new_name);
        let activations: Vec<(RuleId, Severity)> = copy
            .own_activations()
            .map(|(rule, severity)| (rule.clone(), severity))
            .collect();
        let (_before, after) = self.upsert_quality_profile(new_name, &activations).await?;
        Ok(after)
    }

    /// Restores a profile from a backup — issue #22's "Restore profile"
    /// operation. `backup.parent_name`, if set, is resolved against this
    /// instance's profiles; if nothing here has that name (e.g. restoring
    /// onto a fresh instance that never had the parent), the restored
    /// profile ends up parentless rather than the whole restore failing.
    /// A same-named existing profile is left untouched and rejected with
    /// `RestoreProfileError::Conflict` unless `force` is set, in which case
    /// its activations (and parent link) are replaced outright.
    pub async fn restore_quality_profile(
        &self,
        backup: &ProfileBackup,
        force: bool,
    ) -> Result<Vec<(String, String)>, RestoreProfileError> {
        let existing = self.read_quality_profile(&backup.name).await?;
        let parent = match &backup.parent_name {
            Some(parent_name) => self.read_quality_profile(parent_name).await?,
            None => None,
        };
        let policy = if force {
            RestorePolicy::Overwrite
        } else {
            RestorePolicy::Reject
        };
        let restored = yunq_rules_engine::restore(backup, existing.as_ref(), parent, policy)?;

        let parent_id = match restored.parent() {
            Some(parent) => self
                .profile_row_by_name(parent.name())
                .await?
                .map(|(id, _)| id),
            None => None,
        };
        let activations: Vec<(RuleId, Severity)> = restored
            .own_activations()
            .map(|(rule, severity)| (rule.clone(), severity))
            .collect();
        let (_before, after) = self
            .upsert_quality_profile(restored.name(), &activations)
            .await?;

        let profile_id = self
            .profile_row_by_name(restored.name())
            .await?
            .map(|(id, _)| id)
            .ok_or_else(|| {
                StorageError(format!(
                    "profile {:?} vanished right after being written",
                    restored.name()
                ))
            })?;
        sqlx::query("UPDATE quality_profiles SET parent_id = $1 WHERE id = $2")
            .bind(parent_id)
            .bind(profile_id)
            .execute(&self.pool)
            .await
            .map_err(storage_err)?;

        Ok(after)
    }
}

/// `#[ignore]`d by default so `cargo test` needs no database; run explicitly
/// with `cargo test -p yunq-infra-postgres -- --ignored` against
/// `DATABASE_URL`, same convention as `lib.rs`'s `live_db_tests` module.
#[cfg(test)]
mod live_db_tests {
    use yunq_rules_engine::{RestoreError, Severity};

    use super::*;

    async fn connected_storage() -> PgConfigStore {
        let database_url = std::env::var("DATABASE_URL")
            .unwrap_or_else(|_| "postgres://yunq:yunq@localhost:5432/yunq".to_string());
        let storage = PgConfigStore::connect_lazy(&database_url).unwrap();
        storage.migrate().await.unwrap();
        storage
    }

    fn unique_name(prefix: &str) -> String {
        format!(
            "{prefix}-{}",
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        )
    }

    async fn delete_profile(storage: &PgConfigStore, name: &str) {
        sqlx::query("DELETE FROM quality_profiles WHERE name = $1")
            .bind(name)
            .execute(&storage.pool)
            .await
            .unwrap();
    }

    #[tokio::test]
    #[ignore = "requires a live Postgres; see module docs"]
    async fn read_quality_profile_resolves_a_persisted_parent_chain() {
        let storage = connected_storage().await;
        let parent_name = unique_name("profile-parent");
        let child_name = unique_name("profile-child");
        let base_rule = RuleId::new("owasp:eval-usage").unwrap();
        let tuned_rule = RuleId::new("smells:todo-comment").unwrap();

        storage
            .upsert_quality_profile(&parent_name, &[(base_rule.clone(), Severity::Critical)])
            .await
            .unwrap();
        storage
            .upsert_quality_profile(&child_name, &[(tuned_rule.clone(), Severity::Info)])
            .await
            .unwrap();
        // Attach the parent the same way `restore_quality_profile` does —
        // there's no public "set parent" op outside restore, so exercise it
        // through a raw update here (restore's own parent-linking is
        // covered by the restore tests below, which go through the real
        // `ProfileBackup` path end to end).
        let (parent_id, _) = storage.profile_row_by_name(&parent_name).await.unwrap().unwrap();
        let (child_id, _) = storage.profile_row_by_name(&child_name).await.unwrap().unwrap();
        sqlx::query("UPDATE quality_profiles SET parent_id = $1 WHERE id = $2")
            .bind(parent_id)
            .bind(child_id)
            .execute(&storage.pool)
            .await
            .unwrap();

        let profile = storage.read_quality_profile(&child_name).await.unwrap().unwrap();
        assert_eq!(profile.severity_of(&base_rule), Some(Severity::Critical));
        assert_eq!(profile.severity_of(&tuned_rule), Some(Severity::Info));
        assert_eq!(profile.parent().map(|p| p.name().to_string()), Some(parent_name.clone()));

        delete_profile(&storage, &child_name).await;
        delete_profile(&storage, &parent_name).await;
    }

    #[tokio::test]
    #[ignore = "requires a live Postgres; see module docs"]
    async fn read_quality_profile_returns_none_for_an_unknown_name() {
        let storage = connected_storage().await;
        assert!(storage.read_quality_profile(&unique_name("does-not-exist")).await.unwrap().is_none());
    }

    #[tokio::test]
    #[ignore = "requires a live Postgres; see module docs"]
    async fn compare_quality_profiles_diffs_two_stored_profiles() {
        let storage = connected_storage().await;
        let name_a = unique_name("profile-cmp-a");
        let name_b = unique_name("profile-cmp-b");
        let shared_rule = RuleId::new("owasp:eval-usage").unwrap();
        let only_a_rule = RuleId::new("smells:todo-comment").unwrap();

        storage
            .upsert_quality_profile(
                &name_a,
                &[(shared_rule.clone(), Severity::Critical), (only_a_rule.clone(), Severity::Info)],
            )
            .await
            .unwrap();
        storage
            .upsert_quality_profile(&name_b, &[(shared_rule.clone(), Severity::Blocker)])
            .await
            .unwrap();

        let diff = storage.compare_quality_profiles(&name_a, &name_b).await.unwrap();
        assert_eq!(diff.only_in_a, vec![(only_a_rule, Severity::Info)]);
        assert!(diff.only_in_b.is_empty());
        assert_eq!(diff.severity_differs.len(), 1);
        assert_eq!(diff.severity_differs[0].rule, shared_rule);

        delete_profile(&storage, &name_a).await;
        delete_profile(&storage, &name_b).await;
    }

    #[tokio::test]
    #[ignore = "requires a live Postgres; see module docs"]
    async fn compare_quality_profiles_reports_which_side_is_missing() {
        let storage = connected_storage().await;
        let name_a = unique_name("profile-cmp-missing-a");
        let missing = unique_name("profile-cmp-missing-b");
        storage.upsert_quality_profile(&name_a, &[]).await.unwrap();

        let err = storage.compare_quality_profiles(&name_a, &missing).await.unwrap_err();
        assert!(matches!(err, CompareProfileError::NotFound(ProfileNotFoundError(name)) if name == missing));

        delete_profile(&storage, &name_a).await;
    }

    #[tokio::test]
    #[ignore = "requires a live Postgres; see module docs"]
    async fn copy_quality_profile_duplicates_activations_under_a_new_name() {
        let storage = connected_storage().await;
        let source_name = unique_name("profile-copy-source");
        let copy_name = unique_name("profile-copy-target");
        let rule = RuleId::new("owasp:eval-usage").unwrap();

        storage.upsert_quality_profile(&source_name, &[(rule.clone(), Severity::Critical)]).await.unwrap();
        let after = storage.copy_quality_profile(&source_name, &copy_name).await.unwrap();
        assert_eq!(after, vec![(rule.as_str().to_string(), Severity::Critical.as_str().to_string())]);

        let copy = storage.read_quality_profile(&copy_name).await.unwrap().unwrap();
        assert!(copy.parent().is_none());
        assert_eq!(copy.severity_of(&rule), Some(Severity::Critical));

        delete_profile(&storage, &source_name).await;
        delete_profile(&storage, &copy_name).await;
    }

    #[tokio::test]
    #[ignore = "requires a live Postgres; see module docs"]
    async fn restore_quality_profile_roundtrips_a_backup_including_its_parent() {
        let storage = connected_storage().await;
        let parent_name = unique_name("profile-restore-parent");
        let restored_name = unique_name("profile-restore-target");
        let base_rule = RuleId::new("owasp:eval-usage").unwrap();
        let own_rule = RuleId::new("smells:todo-comment").unwrap();

        storage
            .upsert_quality_profile(&parent_name, &[(base_rule.clone(), Severity::Critical)])
            .await
            .unwrap();

        let backup = ProfileBackup {
            name: restored_name.clone(),
            parent_name: Some(parent_name.clone()),
            activations: vec![(own_rule.clone(), Severity::Info)],
        };
        storage.restore_quality_profile(&backup, false).await.unwrap();

        let restored = storage.read_quality_profile(&restored_name).await.unwrap().unwrap();
        assert_eq!(restored.severity_of(&own_rule), Some(Severity::Info));
        assert_eq!(restored.severity_of(&base_rule), Some(Severity::Critical));
        assert_eq!(restored.parent().map(|p| p.name().to_string()), Some(parent_name.clone()));

        delete_profile(&storage, &restored_name).await;
        delete_profile(&storage, &parent_name).await;
    }

    #[tokio::test]
    #[ignore = "requires a live Postgres; see module docs"]
    async fn restore_quality_profile_rejects_a_name_collision_without_force() {
        let storage = connected_storage().await;
        let name = unique_name("profile-restore-collision");
        let rule = RuleId::new("owasp:eval-usage").unwrap();
        storage.upsert_quality_profile(&name, &[(rule.clone(), Severity::Blocker)]).await.unwrap();

        let backup = ProfileBackup {
            name: name.clone(),
            parent_name: None,
            activations: vec![(rule.clone(), Severity::Info)],
        };
        let err = storage.restore_quality_profile(&backup, false).await.unwrap_err();
        assert!(matches!(err, RestoreProfileError::Conflict(RestoreError::NameCollision(n)) if n == name));

        // The existing profile must be untouched by the rejected restore.
        let unchanged = storage.read_quality_profile(&name).await.unwrap().unwrap();
        assert_eq!(unchanged.severity_of(&rule), Some(Severity::Blocker));

        delete_profile(&storage, &name).await;
    }

    #[tokio::test]
    #[ignore = "requires a live Postgres; see module docs"]
    async fn restore_quality_profile_overwrites_when_forced() {
        let storage = connected_storage().await;
        let name = unique_name("profile-restore-force");
        let rule = RuleId::new("owasp:eval-usage").unwrap();
        storage.upsert_quality_profile(&name, &[(rule.clone(), Severity::Blocker)]).await.unwrap();

        let backup = ProfileBackup {
            name: name.clone(),
            parent_name: None,
            activations: vec![(rule.clone(), Severity::Info)],
        };
        storage.restore_quality_profile(&backup, true).await.unwrap();

        let overwritten = storage.read_quality_profile(&name).await.unwrap().unwrap();
        assert_eq!(overwritten.severity_of(&rule), Some(Severity::Info));

        delete_profile(&storage, &name).await;
    }

    #[tokio::test]
    #[ignore = "requires a live Postgres; see module docs"]
    async fn restore_quality_profile_succeeds_parentless_when_the_parent_is_absent() {
        let storage = connected_storage().await;
        let name = unique_name("profile-restore-no-parent");
        let rule = RuleId::new("owasp:eval-usage").unwrap();

        let backup = ProfileBackup {
            name: name.clone(),
            parent_name: Some(unique_name("profile-restore-nonexistent-parent")),
            activations: vec![(rule.clone(), Severity::Info)],
        };
        storage.restore_quality_profile(&backup, false).await.unwrap();

        let restored = storage.read_quality_profile(&name).await.unwrap().unwrap();
        assert!(restored.parent().is_none());
        assert_eq!(restored.severity_of(&rule), Some(Severity::Info));

        delete_profile(&storage, &name).await;
    }
}
