ALTER TABLE issues ADD COLUMN IF NOT EXISTS status     TEXT NOT NULL DEFAULT 'open';
ALTER TABLE issues ADD COLUMN IF NOT EXISTS resolution TEXT NULL;
ALTER TABLE issues ADD COLUMN IF NOT EXISTS assignee   TEXT NULL;

CREATE INDEX IF NOT EXISTS issues_status_idx ON issues (status);
CREATE INDEX IF NOT EXISTS issues_assignee_idx ON issues (assignee);
