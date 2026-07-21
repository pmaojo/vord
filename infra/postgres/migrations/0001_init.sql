CREATE TABLE IF NOT EXISTS issues (
    id          BIGSERIAL PRIMARY KEY,
    rule        TEXT        NOT NULL,
    severity    TEXT        NOT NULL,
    file        TEXT        NOT NULL,
    start_line  INTEGER     NOT NULL,
    start_col   INTEGER     NOT NULL,
    end_line    INTEGER     NOT NULL,
    end_col     INTEGER     NOT NULL,
    message     TEXT        NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS issues_severity_idx ON issues (severity);
CREATE INDEX IF NOT EXISTS issues_rule_idx ON issues (rule);

CREATE TABLE IF NOT EXISTS scan_metrics (
    id              BIGSERIAL PRIMARY KEY,
    files_scanned   INTEGER     NOT NULL,
    files_skipped   INTEGER     NOT NULL,
    parse_failures  INTEGER     NOT NULL,
    lines_of_code   BIGINT      NOT NULL,
    issue_total     INTEGER     NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
