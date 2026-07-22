CREATE TABLE IF NOT EXISTS issue_changelog (
    id          BIGSERIAL PRIMARY KEY,
    issue_id    BIGINT      NOT NULL REFERENCES issues(id) ON DELETE CASCADE,
    action      TEXT        NOT NULL,
    from_status TEXT        NULL,
    transition  TEXT        NULL,
    resolution  TEXT        NULL,
    assignee    TEXT        NULL,
    at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS issue_changelog_issue_id_idx ON issue_changelog (issue_id);
