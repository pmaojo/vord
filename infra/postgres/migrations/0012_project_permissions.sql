-- Per-project permissions: a fixed role ('admin' | 'editor' | 'viewer') per
-- user. Deliberately minimal — no groups, no permission templates, no SSO;
-- those are a separate, larger effort. `project_id` reuses the `projects`
-- table (0007) a project is created there on first permission grant, same
-- as gate assignment does.
CREATE TABLE IF NOT EXISTS project_permissions (
    id          BIGSERIAL   PRIMARY KEY,
    project_id  BIGINT      NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    user_login  TEXT        NOT NULL,
    role        TEXT        NOT NULL, -- 'admin' | 'editor' | 'viewer'
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (project_id, user_login)
);
