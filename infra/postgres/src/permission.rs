//! Outbound adapter: per-project permissions — a fixed role per user.
//! Deliberately minimal (no groups, no templates, no SSO): the whole model
//! is one row per (project, user).

use sqlx::Row;
use yunq_rules_engine::StorageError;

use crate::PgIssueStorage;

fn storage_err(e: impl std::fmt::Display) -> StorageError {
    StorageError(e.to_string())
}

impl PgIssueStorage {
    /// Grants (or changes) a user's role on a project when `role` is
    /// `Some`, revokes it when `None`. The project is created by key on
    /// first sight, same as quality gate assignment. Returns the prior
    /// role, if any, for the audit log.
    pub async fn set_project_permission(
        &self,
        project_key: &str,
        user_login: &str,
        role: Option<&str>,
    ) -> Result<Option<String>, StorageError> {
        let project_id = self.ensure_project(project_key).await?;
        let mut tx = self.pool.begin().await.map_err(storage_err)?;

        let before: Option<String> = sqlx::query(
            "SELECT role FROM project_permissions WHERE project_id = $1 AND user_login = $2",
        )
        .bind(project_id)
        .bind(user_login)
        .fetch_optional(&mut *tx)
        .await
        .map_err(storage_err)?
        .map(|row| row.try_get::<String, _>("role"))
        .transpose()
        .map_err(storage_err)?;

        match role {
            Some(role) => {
                sqlx::query(
                    "INSERT INTO project_permissions (project_id, user_login, role)
                     VALUES ($1, $2, $3)
                     ON CONFLICT (project_id, user_login)
                     DO UPDATE SET role = EXCLUDED.role",
                )
                .bind(project_id)
                .bind(user_login)
                .bind(role)
                .execute(&mut *tx)
                .await
                .map_err(storage_err)?;
            }
            None => {
                sqlx::query(
                    "DELETE FROM project_permissions WHERE project_id = $1 AND user_login = $2",
                )
                .bind(project_id)
                .bind(user_login)
                .execute(&mut *tx)
                .await
                .map_err(storage_err)?;
            }
        }

        tx.commit().await.map_err(storage_err)?;
        Ok(before)
    }
}
