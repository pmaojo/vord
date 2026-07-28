//! What the crate's four adapters have in common.
//!
//! Each adapter owns one bounded context (see `lib.rs`) but they all talk
//! to the same database over the same pool, and a few operations are
//! genuinely shared rather than belonging to any one of them —
//! `ensure_project` in particular, which several contexts need because
//! "the project this is about" is the join key between all of them.
//! Keeping those as free functions over `&PgPool` is what lets the
//! adapters stay independent: an adapter that needs a project id calls
//! this, instead of holding a reference to whichever other adapter
//! happened to own the method.

use sqlx::{PgPool, Row};
use yunq_rules_engine::StorageError;

pub(crate) fn storage_err(e: impl std::fmt::Display) -> StorageError {
    StorageError(e.to_string())
}

/// Looks up a project by key, creating it (with no gate assignment —
/// resolved to the default gate at read time) on first sight. Idempotent:
/// a project already on file is returned unchanged.
pub(crate) async fn ensure_project(pool: &PgPool, key: &str) -> Result<i64, StorageError> {
    let row = sqlx::query(
        "INSERT INTO projects (key, name) VALUES ($1, $1)
         ON CONFLICT (key) DO UPDATE SET key = EXCLUDED.key
         RETURNING id",
    )
    .bind(key)
    .fetch_one(pool)
    .await
    .map_err(storage_err)?;
    row.try_get::<i64, _>("id").map_err(storage_err)
}

/// The gate id explicitly assigned to the project, or (if unassigned) the
/// instance-wide default gate's id, or `None` if neither row exists (a
/// fresh database with migrations not yet seeded).
pub(crate) async fn resolved_gate_id(
    pool: &PgPool,
    project_id: i64,
) -> Result<Option<i64>, StorageError> {
    let assigned: Option<i64> = sqlx::query("SELECT gate_id FROM projects WHERE id = $1")
        .bind(project_id)
        .fetch_optional(pool)
        .await
        .map_err(storage_err)?
        .map(|row| row.try_get::<Option<i64>, _>("gate_id"))
        .transpose()
        .map_err(storage_err)?
        .flatten();

    match assigned {
        Some(id) => Ok(Some(id)),
        None => sqlx::query("SELECT id FROM quality_gates WHERE is_default LIMIT 1")
            .fetch_optional(pool)
            .await
            .map_err(storage_err)?
            .map(|row| row.try_get::<i64, _>("id"))
            .transpose()
            .map_err(storage_err),
    }
}

/// Serializes the `live_db_tests` that reason about whole-table state
/// rather than rows they own. Several of them do — `lib.rs` empties
/// `issues`/`hotspots` and then counts what it inserted, while
/// `retention.rs` inserts issues and hotspots of its own and sweeps them
/// back out — so running them concurrently makes each one's assertions
/// depend on what the others happened to have in flight. Scoping a test
/// to a unique project key isolates its *setup* but not a `DELETE FROM
/// issues` or a `COUNT(*)`. One lock across the modules that share those
/// tables is enough; the whole live suite runs in well under a second
/// either way.
#[cfg(test)]
pub(crate) static WHOLE_TABLE_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Declares an adapter over a Postgres pool: the `new`/`pool` pair and
/// `Clone`, identical for every context, written once. Each adapter is a
/// handle onto the shared pool (`PgPool` is itself reference-counted), so
/// a composition root builds whichever contexts it needs from one
/// connection pool rather than one object that answers for all of them.
macro_rules! pg_adapter {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Clone)]
        pub struct $name {
            pub(crate) pool: sqlx::PgPool,
        }

        impl $name {
            /// Builds the adapter over an existing pool — how a composition
            /// root derives one context from another, with no new
            /// connections.
            pub fn new(pool: sqlx::PgPool) -> Self {
                Self { pool }
            }

            /// Creates the adapter without touching the network;
            /// connections are established on first use.
            pub fn connect_lazy(database_url: &str) -> Result<Self, yunq_rules_engine::StorageError> {
                Ok(Self::new(crate::shared::lazy_pool(database_url)?))
            }

            /// The underlying pool, shared with every other adapter built
            /// from it.
            pub fn pool(&self) -> &sqlx::PgPool {
                &self.pool
            }

            /// Applies the embedded migrations (compiled in at build
            /// time). The schema is database-wide, not per-context, so
            /// running this from any adapter migrates everything —
            /// whichever one a composition root happens to build first.
            pub async fn migrate(&self) -> Result<(), yunq_rules_engine::StorageError> {
                sqlx::migrate!("./migrations")
                    .run(&self.pool)
                    .await
                    .map_err(crate::shared::storage_err)
            }
        }
    };
}

pub(crate) use pg_adapter;

pub(crate) fn lazy_pool(database_url: &str) -> Result<PgPool, StorageError> {
    sqlx::postgres::PgPoolOptions::new()
        .max_connections(5)
        .connect_lazy(database_url)
        .map_err(storage_err)
}
