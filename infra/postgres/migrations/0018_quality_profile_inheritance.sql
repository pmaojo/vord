-- Quality profile inheritance persistence (issue #22: compare/copy/
-- backup-restore). `core/profiles::QualityProfile` has supported a parent
-- chain (`with_parent`) since it was introduced, but 0011 only ever
-- persisted a flat name + activation list — there was no column to
-- remember which profile a stored one inherits from. Backup needs to
-- capture the parent's *name* (a portable reference that survives a
-- restore onto a different yunq instance, unlike this database's row id)
-- and restore needs to reattach a resolved parent when creating the row —
-- both read this column (and the row it references) rather than the name
-- directly, same as `projects.gate_id` referencing `quality_gates(id)`.
ALTER TABLE quality_profiles
    ADD COLUMN IF NOT EXISTS parent_id BIGINT NULL REFERENCES quality_profiles(id) ON DELETE SET NULL;

CREATE INDEX IF NOT EXISTS quality_profiles_parent_id_idx ON quality_profiles (parent_id);
