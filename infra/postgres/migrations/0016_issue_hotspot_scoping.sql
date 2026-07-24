-- Housekeeping (Fase 3), continued: scope `issues`/`hotspots` to a project
-- and (when known at insert time) an analysis, so the same per-project
-- effective-retention purge already built for `analyses`
-- (0015_project_retention.sql, infra/postgres/src/retention.rs) can target
-- them too. Before this migration neither table carried any project/
-- analysis reference at all -- they were a flat table of every finding ever
-- saved, with no "delete findings older than N days for project X" query
-- possible.
--
-- Both columns are nullable. Existing rows predate the concept of a scoped
-- finding and there is no analysis to backfill them from -- guessing a
-- project from, say, the `file` path would be unreliable and silently
-- wrong. They are left NULL instead. `ON DELETE CASCADE` mirrors how
-- `analyses`/`analysis_gate_results` already cascade, so removing a
-- project or analysis cleans up its scoped findings without a separate
-- purge step; a NULL `project_id` is simply never a match for the purge
-- query's join against `projects`, so pre-migration (and any otherwise
-- unscoped) rows are never selected for deletion -- they are kept forever,
-- same as a project with no retention configured.
ALTER TABLE issues ADD COLUMN IF NOT EXISTS project_id BIGINT NULL REFERENCES projects(id) ON DELETE CASCADE;
ALTER TABLE issues ADD COLUMN IF NOT EXISTS analysis_id BIGINT NULL REFERENCES analyses(id) ON DELETE CASCADE;
ALTER TABLE hotspots ADD COLUMN IF NOT EXISTS project_id BIGINT NULL REFERENCES projects(id) ON DELETE CASCADE;
ALTER TABLE hotspots ADD COLUMN IF NOT EXISTS analysis_id BIGINT NULL REFERENCES analyses(id) ON DELETE CASCADE;

-- The purge query filters on project_id and compares created_at against a
-- per-project cutoff, so a composite index serves it directly (and a
-- standalone project_id index covers a future "all findings for this
-- project" lookup that doesn't care about age).
CREATE INDEX IF NOT EXISTS issues_project_id_idx ON issues (project_id);
CREATE INDEX IF NOT EXISTS issues_project_created_at_idx ON issues (project_id, created_at);
CREATE INDEX IF NOT EXISTS hotspots_project_id_idx ON hotspots (project_id);
CREATE INDEX IF NOT EXISTS hotspots_project_created_at_idx ON hotspots (project_id, created_at);
