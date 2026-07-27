//! Quality profile admin operations beyond plain create/update (issue #22):
//! compare two profiles, copy one under a new name, and back up/restore a
//! profile as a portable JSON snapshot (including across yunq instances).
//! Follows the same shape as `ops.rs`'s `upsert_quality_profile` — a thin
//! HTTP layer over `state.ops` (the `OpsStore` port), audit-logged the same
//! way. Kept in its own file since `main.rs`/`ops.rs` are already large and
//! none of this is core system-ops surface.

use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use utoipa::{IntoParams, ToSchema};
use yunq_infra_postgres::{CompareProfileError, CopyProfileError, RestoreProfileError};
use yunq_rules_engine::{ProfileBackup, ProfileDiff, RuleId, Severity};

use crate::AppState;
use crate::auth::Permission;
use crate::auth::permissions::{Caller, is_allowed};

fn actor_from_headers(state: &AppState, headers: &HeaderMap) -> Option<String> {
    state
        .auth
        .authenticate(headers)
        .ok()
        .map(|user| user.username().to_string())
}

fn forbidden(permission: Permission) -> (StatusCode, String) {
    (
        StatusCode::FORBIDDEN,
        format!("missing permission: {permission:?}"),
    )
}

/// One rule activation as `(rule id, severity)`, both stringified — the
/// wire shape for a profile's activation list everywhere in this file.
#[derive(Deserialize, Serialize, ToSchema, Clone)]
pub(crate) struct ActivationDto {
    /// e.g. owasp:eval-usage.
    rule: String,
    /// One of: info, minor, major, critical, blocker.
    severity: String,
}

fn activations_to_dto(activations: &[(String, String)]) -> Vec<ActivationDto> {
    activations
        .iter()
        .map(|(rule, severity)| ActivationDto {
            rule: rule.clone(),
            severity: severity.clone(),
        })
        .collect()
}

#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub(crate) struct CompareQueryDto {
    /// First profile's name.
    a: String,
    /// Second profile's name.
    b: String,
}

#[derive(Serialize, ToSchema)]
pub(crate) struct SeverityDifferenceDto {
    rule: String,
    severity_in_a: String,
    severity_in_b: String,
}

#[derive(Serialize, ToSchema)]
pub(crate) struct ProfileDiffDto {
    /// Active in `a`, inactive in `b`.
    only_in_a: Vec<ActivationDto>,
    /// Active in `b`, inactive in `a`.
    only_in_b: Vec<ActivationDto>,
    /// Active in both, at different severities.
    severity_differs: Vec<SeverityDifferenceDto>,
}

impl From<ProfileDiff> for ProfileDiffDto {
    fn from(diff: ProfileDiff) -> Self {
        Self {
            only_in_a: diff
                .only_in_a
                .into_iter()
                .map(|(rule, severity)| ActivationDto {
                    rule: rule.as_str().to_string(),
                    severity: severity.as_str().to_string(),
                })
                .collect(),
            only_in_b: diff
                .only_in_b
                .into_iter()
                .map(|(rule, severity)| ActivationDto {
                    rule: rule.as_str().to_string(),
                    severity: severity.as_str().to_string(),
                })
                .collect(),
            severity_differs: diff
                .severity_differs
                .into_iter()
                .map(|d| SeverityDifferenceDto {
                    rule: d.rule.as_str().to_string(),
                    severity_in_a: d.severity_in_a.as_str().to_string(),
                    severity_in_b: d.severity_in_b.as_str().to_string(),
                })
                .collect(),
        }
    }
}

/// Compares two profiles' effective (inheritance-resolved) rule
/// activations: which rules are active in one but not the other, and where
/// a shared rule's severity differs.
#[utoipa::path(
    get,
    path = "/api/quality-profiles/compare",
    params(CompareQueryDto),
    responses(
        (status = 200, description = "The diff between the two profiles", body = ProfileDiffDto),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 403, description = "Caller lacks ManageProfiles"),
        (status = 404, description = "One or both profile names don't exist"),
        (status = 502, description = "Storage backend unavailable"),
    )
)]
pub(crate) async fn compare_quality_profiles(
    State(state): State<Arc<AppState>>,
    Query(query): Query<CompareQueryDto>,
    Caller(caller): Caller,
) -> Result<Json<ProfileDiffDto>, (StatusCode, String)> {
    if !is_allowed(&caller, Permission::ManageProfiles) {
        return Err(forbidden(Permission::ManageProfiles));
    }
    let diff = state
        .ops
        .compare_profiles(query.a, query.b)
        .await
        .map_err(|e| match e {
            CompareProfileError::NotFound(not_found) => {
                (StatusCode::NOT_FOUND, not_found.to_string())
            }
            CompareProfileError::Storage(storage) => (StatusCode::BAD_GATEWAY, storage.to_string()),
        })?;
    Ok(Json(diff.into()))
}

#[derive(Deserialize, ToSchema)]
pub(crate) struct ProfileCopyRequestDto {
    /// Name for the new, standalone copy.
    new_name: String,
}

#[derive(Serialize, ToSchema)]
pub(crate) struct ProfileSnapshotDto {
    name: String,
    activations: Vec<ActivationDto>,
}

/// Duplicates a profile's effective (inheritance-resolved) rule
/// activations into a brand-new, standalone profile — no parent link, so
/// later edits to the source never retroactively change the copy. If a
/// profile already exists under `new_name`, its activations are replaced
/// (same "create or update" semantics as `PUT /api/quality-profiles/{name}`
/// — copy is just that write path with its input read from another
/// profile instead of the request body); audit-logged as `profile.copied`.
#[utoipa::path(
    post,
    path = "/api/quality-profiles/{name}/copy",
    params(("name" = String, Path, description = "Source profile name")),
    request_body = ProfileCopyRequestDto,
    responses(
        (status = 200, description = "The new copy", body = ProfileSnapshotDto),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 403, description = "Caller lacks ManageProfiles"),
        (status = 404, description = "No profile named `name`"),
        (status = 502, description = "Storage backend unavailable"),
    )
)]
pub(crate) async fn copy_quality_profile(
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
    headers: HeaderMap,
    Caller(caller): Caller,
    Json(request): Json<ProfileCopyRequestDto>,
) -> Result<Json<ProfileSnapshotDto>, (StatusCode, String)> {
    if !is_allowed(&caller, Permission::ManageProfiles) {
        return Err(forbidden(Permission::ManageProfiles));
    }
    let actor = actor_from_headers(&state, &headers);
    let after = state
        .ops
        .copy_profile(name.clone(), request.new_name.clone())
        .await
        .map_err(|e| match e {
            CopyProfileError::NotFound(not_found) => (StatusCode::NOT_FOUND, not_found.to_string()),
            CopyProfileError::Storage(storage) => (StatusCode::BAD_GATEWAY, storage.to_string()),
        })?;

    state
        .ops
        .record_audit(
            actor,
            "profile.copied".to_string(),
            "quality_profile".to_string(),
            request.new_name.clone(),
            Some(Value::String(name)),
            Some(serde_json::to_value(activations_to_dto(&after)).unwrap_or(Value::Null)),
        )
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, e.to_string()))?;

    Ok(Json(ProfileSnapshotDto {
        name: request.new_name,
        activations: activations_to_dto(&after),
    }))
}

/// Portable backup format: a profile's name, its own (non-inherited)
/// activations, and its parent's name if it has one. Restoring this same
/// shape (via `POST /api/quality-profiles/restore`) reconstructs the
/// profile, resolving the parent by name on whichever instance it's
/// restored to — deliberately not a foreign-key/id reference, so a backup
/// downloaded from one yunq instance can be uploaded to another.
#[derive(Deserialize, Serialize, ToSchema)]
pub(crate) struct ProfileBackupDto {
    name: String,
    parent_name: Option<String>,
    activations: Vec<ActivationDto>,
}

fn activation_dtos_to_core(
    activations: &[ActivationDto],
) -> Result<Vec<(RuleId, Severity)>, (StatusCode, String)> {
    activations
        .iter()
        .map(|a| {
            let rule =
                RuleId::new(&a.rule).map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
            let severity = Severity::parse(&a.severity).ok_or_else(|| {
                (
                    StatusCode::BAD_REQUEST,
                    format!(
                        "invalid severity {:?} (info|minor|major|critical|blocker)",
                        a.severity
                    ),
                )
            })?;
            Ok((rule, severity))
        })
        .collect()
}

/// Downloads a profile as a portable JSON backup — own activations only
/// (not inherited ones, same convention as the domain type this mirrors,
/// `yunq_profiles::ProfileBackup`) plus its parent's name.
#[utoipa::path(
    get,
    path = "/api/quality-profiles/{name}/backup",
    params(("name" = String, Path, description = "Profile name")),
    responses(
        (status = 200, description = "Portable backup of the profile", body = ProfileBackupDto),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 403, description = "Caller lacks ManageProfiles"),
        (status = 404, description = "No profile named `name`"),
        (status = 502, description = "Storage backend unavailable"),
    )
)]
pub(crate) async fn backup_quality_profile(
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
    Caller(caller): Caller,
) -> Result<Json<ProfileBackupDto>, (StatusCode, String)> {
    if !is_allowed(&caller, Permission::ManageProfiles) {
        return Err(forbidden(Permission::ManageProfiles));
    }
    let profile = state
        .ops
        .read_profile(name.clone())
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, e.to_string()))?
        .ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                format!("no quality profile named {name:?}"),
            )
        })?;

    let backup = yunq_rules_engine::backup(&profile);
    Ok(Json(ProfileBackupDto {
        name: backup.name,
        parent_name: backup.parent_name,
        activations: backup
            .activations
            .into_iter()
            .map(|(rule, severity)| ActivationDto {
                rule: rule.as_str().to_string(),
                severity: severity.as_str().to_string(),
            })
            .collect(),
    }))
}

#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub(crate) struct RestoreQueryDto {
    /// Overwrite an existing same-named profile instead of rejecting the
    /// restore. Defaults to `false` — restoring never silently clobbers.
    #[serde(default)]
    force: bool,
}

/// Restores a profile from a backup produced by
/// `GET /api/quality-profiles/{name}/backup` (on this instance or another
/// one). If a profile already exists under the backup's name, the restore
/// is rejected with `409 Conflict` unless `?force=true`; the backup's
/// `parent_name`, if set, is resolved against this instance's profiles —
/// if nothing here has that name, the restored profile ends up parentless
/// rather than the whole restore failing (so a backup taken on one
/// instance still restores cleanly on another that never had the parent).
/// Audit-logged as `profile.restored`.
#[utoipa::path(
    post,
    path = "/api/quality-profiles/restore",
    params(RestoreQueryDto),
    request_body = ProfileBackupDto,
    responses(
        (status = 200, description = "The restored profile", body = ProfileSnapshotDto),
        (status = 400, description = "Invalid rule id or severity in the backup"),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 403, description = "Caller lacks ManageProfiles"),
        (status = 409, description = "A profile with this name already exists; retry with force=true"),
        (status = 502, description = "Storage backend unavailable"),
    )
)]
pub(crate) async fn restore_quality_profile(
    State(state): State<Arc<AppState>>,
    Query(query): Query<RestoreQueryDto>,
    headers: HeaderMap,
    Caller(caller): Caller,
    Json(request): Json<ProfileBackupDto>,
) -> Result<Json<ProfileSnapshotDto>, (StatusCode, String)> {
    if !is_allowed(&caller, Permission::ManageProfiles) {
        return Err(forbidden(Permission::ManageProfiles));
    }
    let activations = activation_dtos_to_core(&request.activations)?;
    let backup = ProfileBackup {
        name: request.name.clone(),
        parent_name: request.parent_name.clone(),
        activations,
    };
    let actor = actor_from_headers(&state, &headers);

    let after = state
        .ops
        .restore_profile(backup, query.force)
        .await
        .map_err(|e| match e {
            RestoreProfileError::Conflict(conflict) => (StatusCode::CONFLICT, conflict.to_string()),
            RestoreProfileError::Storage(storage) => (StatusCode::BAD_GATEWAY, storage.to_string()),
        })?;

    state
        .ops
        .record_audit(
            actor,
            "profile.restored".to_string(),
            "quality_profile".to_string(),
            request.name.clone(),
            None,
            Some(serde_json::to_value(activations_to_dto(&after)).unwrap_or(Value::Null)),
        )
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, e.to_string()))?;

    Ok(Json(ProfileSnapshotDto {
        name: request.name,
        activations: activations_to_dto(&after),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn activation_dtos_to_core_rejects_an_invalid_severity() {
        let dtos = vec![ActivationDto {
            rule: "owasp:eval-usage".to_string(),
            severity: "urgent".to_string(),
        }];
        assert!(activation_dtos_to_core(&dtos).is_err());
    }

    #[test]
    fn activation_dtos_to_core_rejects_an_invalid_rule_id() {
        let dtos = vec![ActivationDto {
            rule: "not-namespaced".to_string(),
            severity: "major".to_string(),
        }];
        assert!(activation_dtos_to_core(&dtos).is_err());
    }
}
