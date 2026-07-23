-- Persisted coverage summary for one analysis, ingested server-side via
-- POST /api/projects/{key}/coverage instead of only being computable
-- locally by the CLI. Branch totals are 0 for reports/formats that carry
-- no branch data, same "absent means not reported" convention as the
-- domain's CoverageSummary::percent_branches().
CREATE TABLE IF NOT EXISTS analysis_coverage (
    id                 BIGSERIAL PRIMARY KEY,
    analysis_id        BIGINT      NOT NULL REFERENCES analyses(id) ON DELETE CASCADE,
    covered_lines      BIGINT      NOT NULL DEFAULT 0,
    coverable_lines    BIGINT      NOT NULL DEFAULT 0,
    covered_branches   BIGINT      NOT NULL DEFAULT 0,
    coverable_branches BIGINT      NOT NULL DEFAULT 0,
    recorded_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- One coverage summary per analysis; re-ingesting (e.g. a re-uploaded
-- report) replaces it rather than accumulating duplicates.
CREATE UNIQUE INDEX IF NOT EXISTS analysis_coverage_analysis_id_idx
    ON analysis_coverage (analysis_id);
