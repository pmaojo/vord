-- Housekeeping (Fase 3): configurable retention for analysis history.
-- `retention_days = NULL` means "use the instance-wide default passed into
-- the purge job", same "unassigned falls through" convention `gate_id`
-- already uses. An instance with no default set either purges nothing.
ALTER TABLE projects ADD COLUMN IF NOT EXISTS retention_days INT NULL;
