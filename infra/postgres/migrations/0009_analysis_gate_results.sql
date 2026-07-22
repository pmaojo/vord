-- Persisted outcome of evaluating a project's quality gate against one
-- analysis. `conditions` is the full per-condition detail (metric, operator,
-- threshold, measured value, status) as a JSON array, so the API/UI can show
-- exactly which conditions failed without recomputing anything.
CREATE TABLE IF NOT EXISTS analysis_gate_results (
    id             BIGSERIAL PRIMARY KEY,
    analysis_id    BIGINT      NOT NULL REFERENCES analyses(id) ON DELETE CASCADE,
    status         TEXT        NOT NULL, -- 'passed' | 'failed'
    conditions     JSONB       NOT NULL,
    evaluated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- One gate result per analysis.
CREATE UNIQUE INDEX IF NOT EXISTS analysis_gate_results_analysis_id_idx
    ON analysis_gate_results (analysis_id);
