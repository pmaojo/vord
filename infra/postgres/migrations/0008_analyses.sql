-- One row per completed analysis run of a project on a branch — the unit
-- the quality gate result and the "new code" definition are scoped to.
CREATE TABLE IF NOT EXISTS analyses (
    id             BIGSERIAL PRIMARY KEY,
    project_id     BIGINT      NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    branch         TEXT        NOT NULL DEFAULT 'main',
    lines_of_code  BIGINT      NOT NULL DEFAULT 0,
    issue_total    INTEGER     NOT NULL DEFAULT 0,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS analyses_project_branch_idx ON analyses (project_id, branch, id DESC);
