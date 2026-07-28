//! Per-project (and optionally per-branch) New Code definition: which prior
//! analysis a scan's issues get classified against for the `new_*` gate
//! measures (see `yunq_rules_engine::NewCodeAnalysis`, wired into the
//! worker's `persist_gate_result`).
//!
//! Same shape as `ops.rs`'s other project-scoped admin writes (retention,
//! permission grants): `AdminAccess`-gated, audit-logged, backed by
//! `state.ops` (the `OpsStore` port). Kept in its own file for the same
//! reason `ai_provider_admin` is — one focused admin surface rather than
//! ops.rs accreting every project setting.

use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use yunq_rules_engine::{BranchName, NewCodeDefinition};

use crate::auth::permissions::{is_allowed, Caller};
use crate::auth::Permission;
use crate::AppState;

/// Matches `DEFAULT_BRANCH` in `bin/worker`: every scan is currently
/// recorded against this branch, so it's the one whose effective
/// definition actually drives a real gate evaluation until scans carry a
/// real branch name.
const DEFAULT_BRANCH: &str = "main";

fn actor_from_headers(state: &AppState, headers: &HeaderMap) -> Option<String> {
    state.auth.authenticate(headers).ok().map(|user| user.username().to_string())
}

fn forbidden(permission: Permission) -> (StatusCode, String) {
    (StatusCode::FORBIDDEN, format!("missing permission: {permission:?}"))
}

/// JSON shape of a `NewCodeDefinition`. `rename_all = "snake_case"` on the
/// `kind` tag happens to match the Postgres `kind` column's own encoding
/// (`new_code_definitions.kind`) exactly.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(crate) enum NewCodeDefinitionDto {
    /// New code is everything since the previous analysis on this branch.
    PreviousAnalysis,
    /// New code is everything from the last `days` days.
    NumberOfDays { days: u32 },
    /// New code is the diff against a long-lived reference branch.
    ReferenceBranch { branch: String },
    /// New code is everything since a specific analysis id.
    SpecificAnalysis { analysis_id: String },
}

impl NewCodeDefinitionDto {
    fn into_domain(self) -> Result<NewCodeDefinition, (StatusCode, String)> {
        Ok(match self {
            Self::PreviousAnalysis => NewCodeDefinition::PreviousAnalysis,
            Self::NumberOfDays { days } => NewCodeDefinition::NumberOfDays(days),
            Self::ReferenceBranch { branch } => NewCodeDefinition::ReferenceBranch(
                BranchName::new(&branch).map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?,
            ),
            Self::SpecificAnalysis { analysis_id } => NewCodeDefinition::SpecificAnalysis(analysis_id),
        })
    }

    fn from_domain(definition: NewCodeDefinition) -> Self {
        match definition {
            NewCodeDefinition::PreviousAnalysis => Self::PreviousAnalysis,
            NewCodeDefinition::NumberOfDays(days) => Self::NumberOfDays { days },
            NewCodeDefinition::ReferenceBranch(branch) => {
                Self::ReferenceBranch { branch: branch.as_str().to_string() }
            }
            NewCodeDefinition::SpecificAnalysis(analysis_id) => Self::SpecificAnalysis { analysis_id },
        }
    }
}

#[derive(Serialize, ToSchema)]
pub(crate) struct NewCodeDefinitionResponseDto {
    project_key: String,
    /// The branch this effective definition was resolved for (or, for a
    /// `PUT` with no `for_branch`, the project-wide default's own label).
    branch: String,
    definition: NewCodeDefinitionDto,
}

#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub(crate) struct NewCodeDefinitionQueryDto {
    /// Branch to resolve the effective definition for. Defaults to `main`
    /// — every scan is currently recorded against that branch (see
    /// `DEFAULT_BRANCH`), so it's the one whose effective definition
    /// actually drives a real gate evaluation.
    branch: Option<String>,
}

/// Reads the effective New Code definition for a project/branch: its own
/// branch-specific override, else the project-wide default, else the
/// built-in default (`previous_analysis`) — same precedence
/// `PgAnalysisStore::resolve_new_code_definition` applies at scan time.
#[utoipa::path(
    get,
    path = "/api/projects/{key}/new-code-definition",
    params(
        ("key" = String, Path, description = "Project key"),
        NewCodeDefinitionQueryDto,
    ),
    responses(
        (status = 200, description = "The effective New Code definition", body = NewCodeDefinitionResponseDto),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 403, description = "Caller lacks AdminAccess"),
        (status = 502, description = "Storage backend unavailable"),
    )
)]
pub(crate) async fn get_new_code_definition(
    State(state): State<Arc<AppState>>,
    Path(key): Path<String>,
    Query(query): Query<NewCodeDefinitionQueryDto>,
    Caller(caller): Caller,
) -> Result<Json<NewCodeDefinitionResponseDto>, (StatusCode, String)> {
    if !is_allowed(&caller, Permission::AdminAccess) {
        return Err(forbidden(Permission::AdminAccess));
    }
    let branch = query.branch.unwrap_or_else(|| DEFAULT_BRANCH.to_string());

    let definition = state
        .ops
        .new_code_definition(key.clone(), branch.clone())
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, e.to_string()))?;

    Ok(Json(NewCodeDefinitionResponseDto {
        project_key: key,
        branch,
        definition: NewCodeDefinitionDto::from_domain(definition),
    }))
}

#[derive(Debug, PartialEq, Eq, Deserialize, ToSchema)]
pub(crate) struct SetNewCodeDefinitionRequestDto {
    /// Branch this override applies to; omit to set the project-wide
    /// default that any branch without its own override falls back to.
    for_branch: Option<String>,
    #[serde(flatten)]
    definition: NewCodeDefinitionDto,
}

/// Assigns a project's (or one branch's) New Code definition; audit-logged
/// as `project.new_code_definition_updated`.
#[utoipa::path(
    put,
    path = "/api/projects/{key}/new-code-definition",
    params(("key" = String, Path, description = "Project key")),
    request_body = SetNewCodeDefinitionRequestDto,
    responses(
        (status = 200, description = "The definition after the update", body = NewCodeDefinitionResponseDto),
        (status = 400, description = "Invalid branch name"),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 403, description = "Caller lacks AdminAccess"),
        (status = 502, description = "Storage backend unavailable"),
    )
)]
pub(crate) async fn set_new_code_definition(
    State(state): State<Arc<AppState>>,
    Path(key): Path<String>,
    headers: HeaderMap,
    Caller(caller): Caller,
    Json(request): Json<SetNewCodeDefinitionRequestDto>,
) -> Result<Json<NewCodeDefinitionResponseDto>, (StatusCode, String)> {
    if !is_allowed(&caller, Permission::AdminAccess) {
        return Err(forbidden(Permission::AdminAccess));
    }
    let actor = actor_from_headers(&state, &headers);
    let definition = request.definition.into_domain()?;

    state
        .ops
        .set_new_code_definition(key.clone(), request.for_branch.clone(), definition.clone())
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, e.to_string()))?;

    let entity_id = match &request.for_branch {
        Some(branch) => format!("{key}:{branch}"),
        None => key.clone(),
    };
    state
        .ops
        .record_audit(
            actor,
            "project.new_code_definition_updated".to_string(),
            "project".to_string(),
            entity_id,
            None,
            Some(serde_json::json!({
                "branch": request.for_branch,
                "definition": NewCodeDefinitionDto::from_domain(definition.clone()),
            })),
        )
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, e.to_string()))?;

    Ok(Json(NewCodeDefinitionResponseDto {
        project_key: key,
        branch: request.for_branch.unwrap_or_else(|| DEFAULT_BRANCH.to_string()),
        definition: NewCodeDefinitionDto::from_domain(definition),
    }))
}

#[derive(Serialize, ToSchema)]
pub(crate) struct GlobalNewCodeDefinitionResponseDto {
    /// `None` when no instance-wide default has been set — every project
    /// then resolves through its own default, or the built-in
    /// `previous_analysis` if it has none either.
    definition: Option<NewCodeDefinitionDto>,
}

/// Reads the instance-wide default New Code definition, if one has been
/// set — distinct from a project's *effective* definition
/// (`GET /api/projects/{key}/new-code-definition`), which also folds in
/// any project/branch override.
#[utoipa::path(
    get,
    path = "/api/system/new-code-definition",
    responses(
        (status = 200, description = "The instance-wide default, if set", body = GlobalNewCodeDefinitionResponseDto),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 403, description = "Caller lacks AdminAccess"),
        (status = 502, description = "Storage backend unavailable"),
    )
)]
pub(crate) async fn get_global_new_code_definition(
    State(state): State<Arc<AppState>>,
    Caller(caller): Caller,
) -> Result<Json<GlobalNewCodeDefinitionResponseDto>, (StatusCode, String)> {
    if !is_allowed(&caller, Permission::AdminAccess) {
        return Err(forbidden(Permission::AdminAccess));
    }
    let definition = state
        .ops
        .global_new_code_definition()
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, e.to_string()))?;

    Ok(Json(GlobalNewCodeDefinitionResponseDto {
        definition: definition.map(NewCodeDefinitionDto::from_domain),
    }))
}

/// Sets the instance-wide default New Code definition, applied to any
/// project/branch with no override of its own; audit-logged as
/// `system.new_code_definition_updated`.
#[utoipa::path(
    put,
    path = "/api/system/new-code-definition",
    request_body = NewCodeDefinitionDto,
    responses(
        (status = 200, description = "The instance-wide default after the update", body = GlobalNewCodeDefinitionResponseDto),
        (status = 400, description = "Invalid branch name"),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 403, description = "Caller lacks AdminAccess"),
        (status = 502, description = "Storage backend unavailable"),
    )
)]
pub(crate) async fn set_global_new_code_definition(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Caller(caller): Caller,
    Json(request): Json<NewCodeDefinitionDto>,
) -> Result<Json<GlobalNewCodeDefinitionResponseDto>, (StatusCode, String)> {
    if !is_allowed(&caller, Permission::AdminAccess) {
        return Err(forbidden(Permission::AdminAccess));
    }
    let actor = actor_from_headers(&state, &headers);
    let definition = request.into_domain()?;

    state
        .ops
        .set_global_new_code_definition(definition.clone())
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, e.to_string()))?;

    state
        .ops
        .record_audit(
            actor,
            "system.new_code_definition_updated".to_string(),
            "instance".to_string(),
            "global".to_string(),
            None,
            Some(serde_json::json!({ "definition": NewCodeDefinitionDto::from_domain(definition.clone()) })),
        )
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, e.to_string()))?;

    Ok(Json(GlobalNewCodeDefinitionResponseDto {
        definition: Some(NewCodeDefinitionDto::from_domain(definition)),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dto_round_trips_through_domain_for_every_variant() {
        let cases = [
            NewCodeDefinitionDto::PreviousAnalysis,
            NewCodeDefinitionDto::NumberOfDays { days: 30 },
            NewCodeDefinitionDto::ReferenceBranch { branch: "develop".to_string() },
            NewCodeDefinitionDto::SpecificAnalysis { analysis_id: "42".to_string() },
        ];
        for dto in cases {
            let domain = dto.clone().into_domain().expect("valid dto");
            assert_eq!(NewCodeDefinitionDto::from_domain(domain), dto);
        }
    }

    #[test]
    fn reference_branch_with_whitespace_is_rejected() {
        let dto = NewCodeDefinitionDto::ReferenceBranch { branch: "has space".to_string() };
        let (status, _) = dto.into_domain().unwrap_err();
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[test]
    fn previous_analysis_deserializes_from_just_the_kind_tag() {
        let dto: NewCodeDefinitionDto = serde_json::from_str(r#"{"kind":"previous_analysis"}"#).unwrap();
        assert_eq!(dto, NewCodeDefinitionDto::PreviousAnalysis);
    }

    #[test]
    fn number_of_days_deserializes_tag_plus_payload() {
        let dto: NewCodeDefinitionDto =
            serde_json::from_str(r#"{"kind":"number_of_days","days":14}"#).unwrap();
        assert_eq!(dto, NewCodeDefinitionDto::NumberOfDays { days: 14 });
    }

    /// The field the request body actually exercises `#[serde(flatten)]`
    /// for: `SetNewCodeDefinitionRequestDto`'s own `for_branch` sits
    /// alongside the flattened, internally-tagged `NewCodeDefinitionDto` —
    /// a combination serde has had rough edges with historically. Verifying
    /// it round-trips through real JSON (not just that it compiles) for
    /// both a scoped and an unscoped request.
    #[test]
    fn set_request_flattens_definition_alongside_for_branch() {
        let scoped: SetNewCodeDefinitionRequestDto = serde_json::from_str(
            r#"{"for_branch":"develop","kind":"reference_branch","branch":"main"}"#,
        )
        .unwrap();
        assert_eq!(
            scoped,
            SetNewCodeDefinitionRequestDto {
                for_branch: Some("develop".to_string()),
                definition: NewCodeDefinitionDto::ReferenceBranch { branch: "main".to_string() },
            }
        );

        let unscoped: SetNewCodeDefinitionRequestDto =
            serde_json::from_str(r#"{"kind":"number_of_days","days":7}"#).unwrap();
        assert_eq!(
            unscoped,
            SetNewCodeDefinitionRequestDto {
                for_branch: None,
                definition: NewCodeDefinitionDto::NumberOfDays { days: 7 },
            }
        );
    }

    #[test]
    fn global_response_serializes_unset_as_null_not_a_missing_field() {
        let unset = serde_json::to_value(GlobalNewCodeDefinitionResponseDto { definition: None }).unwrap();
        assert_eq!(unset, serde_json::json!({ "definition": null }));

        let set = serde_json::to_value(GlobalNewCodeDefinitionResponseDto {
            definition: Some(NewCodeDefinitionDto::NumberOfDays { days: 14 }),
        })
        .unwrap();
        assert_eq!(set, serde_json::json!({ "definition": { "kind": "number_of_days", "days": 14 } }));
    }
}
