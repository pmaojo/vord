-- Instance-wide default New Code definition, applied when a project has
-- neither a branch-specific override nor a project-wide default of its own
-- in `new_code_definitions`. A dedicated singleton table rather than a
-- nullable `project_id` on `new_code_definitions`, so the existing
-- per-project precedence query and its FK/cascade behavior are untouched.
-- The fixed primary key enforces "at most one row".
CREATE TABLE IF NOT EXISTS global_new_code_definition (
    id         SMALLINT PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    kind       TEXT NOT NULL, -- previous_analysis | number_of_days | reference_branch | specific_analysis
    param      TEXT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
