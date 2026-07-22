-- Ops audit log (Fase 4): who changed what and when, for quality gates,
-- quality profiles and project permissions. `before`/`after` are the
-- changed entity's state as JSON, so the API can show a diff without
-- recomputing anything (same idea as `analysis_gate_results.conditions`).
CREATE TABLE IF NOT EXISTS audit_log (
    id             BIGSERIAL   PRIMARY KEY,
    actor_user_id  TEXT        NULL,
    action         TEXT        NOT NULL, -- e.g. gate.updated, profile.updated, permission.granted
    entity_type    TEXT        NOT NULL, -- quality_gate | quality_profile | project_permission
    entity_id      TEXT        NOT NULL,
    before         JSONB       NULL,
    after          JSONB       NULL,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS audit_log_entity_type_idx ON audit_log (entity_type);
CREATE INDEX IF NOT EXISTS audit_log_created_at_idx ON audit_log (created_at);
