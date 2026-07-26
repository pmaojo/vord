-- Per-line SCM blame detail (issue #26's now-unblocked follow-up: #33 added
-- blame capture to the CLI's `--blame-output`, but nothing persisted it
-- server-side, so the `sources` endpoint had no blame to annotate with).
-- Same shape/conventions as `analysis_file_coverage_lines` (0017): one row
-- per (analysis, file, line), scoped through `analysis_id` so blame never
-- leaks across projects, ingested by `POST /api/projects/{key}/blame` from
-- the CLI's own JSON output — no new capture mechanism, just a place to put
-- what the CLI already computes.
CREATE TABLE IF NOT EXISTS analysis_file_blame_lines (
    id           BIGSERIAL PRIMARY KEY,
    analysis_id  BIGINT      NOT NULL REFERENCES analyses(id) ON DELETE CASCADE,
    file         TEXT        NOT NULL,
    line_number  INTEGER     NOT NULL,
    commit_sha   TEXT        NOT NULL,
    author       TEXT        NOT NULL,
    author_mail  TEXT        NOT NULL,
    author_time  BIGINT      NOT NULL,
    summary      TEXT        NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Re-ingesting blame for the same analysis replaces its line detail rather
-- than accumulating duplicates (same convention as coverage lines).
CREATE UNIQUE INDEX IF NOT EXISTS analysis_file_blame_lines_unique_idx
    ON analysis_file_blame_lines (analysis_id, file, line_number);

CREATE INDEX IF NOT EXISTS analysis_file_blame_lines_lookup_idx
    ON analysis_file_blame_lines (analysis_id, file);
