-- Projects as first-class entities: a project key (as already used by
-- scan_jobs.project) plus its quality gate assignment. `gate_id` NULL means
-- "use the default gate" (resolved at read time, never copied down), so a
-- change to the default gate takes effect for every unassigned project.
CREATE TABLE IF NOT EXISTS projects (
    id          BIGSERIAL PRIMARY KEY,
    key         TEXT        NOT NULL UNIQUE,
    name        TEXT        NOT NULL,
    gate_id     BIGINT      NULL REFERENCES quality_gates(id) ON DELETE SET NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
