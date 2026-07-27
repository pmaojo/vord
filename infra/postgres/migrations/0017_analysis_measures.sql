-- Per-analysis measure history (issue #26): the measure-history and
-- component-tree endpoints need a time series of scalar
-- measures per analysis, which nothing before this
-- migration persisted — `analyses` only ever carried a couple of summary
-- columns (`lines_of_code`, `issue_total`).
--
-- One row per (analysis, component, metric). `component IS NULL` is the
-- project-level measure (the whole analysis, e.g. `coverage`,
-- `duplicated_lines_density`); a non-NULL `component` is a per-file path,
-- scoped to that specific analysis so component-tree/file listings never
-- leak across projects the way a flat, unscoped table would (the existing
-- `issues` table has no project/analysis linkage at all — seeing this
-- table's rows always go through `analysis_id`, and from there to
-- `analyses.project_id`, is what keeps file lists project-safe).
CREATE TABLE IF NOT EXISTS analysis_measures (
    id            BIGSERIAL PRIMARY KEY,
    analysis_id   BIGINT           NOT NULL REFERENCES analyses(id) ON DELETE CASCADE,
    component     TEXT             NULL,
    measure_key   TEXT             NOT NULL,
    measure_value DOUBLE PRECISION NOT NULL,
    created_at    TIMESTAMPTZ      NOT NULL DEFAULT now()
);

-- Re-persisting measures for the same analysis (shouldn't normally happen —
-- an analysis is written once — but keeps the write idempotent) replaces
-- rather than duplicates, same convention as `analysis_coverage`.
CREATE UNIQUE INDEX IF NOT EXISTS analysis_measures_unique_idx
    ON analysis_measures (analysis_id, COALESCE(component, ''), measure_key);

-- Component tree: "every component measured in this analysis".
CREATE INDEX IF NOT EXISTS analysis_measures_analysis_idx ON analysis_measures (analysis_id);

-- Measure history: "this metric's value across a project's analyses" scans
-- by key across many analyses of the same project-level (component IS NULL)
-- rows, joined through `analyses.project_id`.
CREATE INDEX IF NOT EXISTS analysis_measures_key_idx ON analysis_measures (measure_key, analysis_id);

-- Per-line coverage detail (line -> hit count), ingested alongside the
-- existing `analysis_coverage` summary by `POST /api/projects/{key}/coverage`.
-- `analysis_coverage` only ever stored the report-wide totals, so the
-- `sources` endpoint's per-line coverage annotation had nothing to read;
-- `yunq_infra_fs::parse_coverage_report` already computes this per-file/
-- per-line detail (`CoverageReport::files`), it was just discarded after
-- reducing to the summary. Storing raw source line *text* is out of scope
-- for this migration/feature slice (yunq's server never persists checked-
-- out source content at all, only derived data) — this table stores line
-- *numbers* and hit counts to annotate a line, not the line's text.
CREATE TABLE IF NOT EXISTS analysis_file_coverage_lines (
    id           BIGSERIAL PRIMARY KEY,
    analysis_id  BIGINT      NOT NULL REFERENCES analyses(id) ON DELETE CASCADE,
    file         TEXT        NOT NULL,
    line_number  INTEGER     NOT NULL,
    hits         INTEGER     NOT NULL DEFAULT 0,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Re-ingesting a coverage report for the same analysis replaces its line
-- detail rather than accumulating duplicates (same convention as
-- `analysis_coverage`'s own upsert).
CREATE UNIQUE INDEX IF NOT EXISTS analysis_file_coverage_lines_unique_idx
    ON analysis_file_coverage_lines (analysis_id, file, line_number);

CREATE INDEX IF NOT EXISTS analysis_file_coverage_lines_lookup_idx
    ON analysis_file_coverage_lines (analysis_id, file);
