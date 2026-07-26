-- Per-project activity log (Fase 4, issue #30): a durable, human-readable
-- record of what a project's background tasks did — scan started/
-- succeeded/failed today, more event types (webhook deliveries, gate
-- changes, ...) later without a schema change, since `metadata` is JSONB.
-- Separate from `audit_log` (0013): that table is instance-wide admin
-- actions (who changed a gate/profile/permission); this one is per-project
-- system activity, scoped by `project_id` and read back per project.
CREATE TABLE IF NOT EXISTS activity_log (
    id          BIGSERIAL   PRIMARY KEY,
    project_id  BIGINT      NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    event_type  TEXT        NOT NULL, -- e.g. scan.started, scan.succeeded, scan.failed
    message     TEXT        NOT NULL,
    metadata    JSONB       NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS activity_log_project_idx ON activity_log (project_id, id DESC);
