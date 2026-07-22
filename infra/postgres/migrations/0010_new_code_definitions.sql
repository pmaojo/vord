-- "New Code" (Clean as You Code) definition assignment, mirroring
-- `yunq_rules_engine::NewCodeDefinition`'s four modes. `branch = NULL` is the
-- project-wide default; a row with a specific branch overrides it for that
-- branch only. `param` carries the mode-specific payload as text: the day
-- count, the reference branch name, or the specific analysis id.
CREATE TABLE IF NOT EXISTS new_code_definitions (
    id          BIGSERIAL PRIMARY KEY,
    project_id  BIGINT      NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    branch      TEXT        NULL,
    kind        TEXT        NOT NULL, -- previous_analysis | number_of_days | reference_branch | specific_analysis
    param       TEXT        NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS new_code_definitions_project_branch_idx
    ON new_code_definitions (project_id, (COALESCE(branch, '')));
