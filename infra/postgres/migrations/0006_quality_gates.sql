-- Quality gates: named condition sets, mirroring core/profiles::QualityGate.
-- One gate is seeded as the built-in default (matches
-- `yunq_rules_engine::default_gate()` / `yunq_cli::default_quality_gate()`)
-- so every project has an effective gate even before an admin assigns one.
CREATE TABLE IF NOT EXISTS quality_gates (
    id          BIGSERIAL PRIMARY KEY,
    name        TEXT        NOT NULL UNIQUE,
    is_default  BOOLEAN     NOT NULL DEFAULT false,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Only one gate may be the default at a time.
CREATE UNIQUE INDEX IF NOT EXISTS quality_gates_single_default_idx
    ON quality_gates (is_default) WHERE is_default;

CREATE TABLE IF NOT EXISTS quality_gate_conditions (
    id          BIGSERIAL PRIMARY KEY,
    gate_id     BIGINT           NOT NULL REFERENCES quality_gates(id) ON DELETE CASCADE,
    metric      TEXT             NOT NULL,
    operator    TEXT             NOT NULL, -- 'gt' | 'lt', see ComparisonOperator
    threshold   DOUBLE PRECISION NOT NULL
);

CREATE INDEX IF NOT EXISTS quality_gate_conditions_gate_id_idx ON quality_gate_conditions (gate_id);

INSERT INTO quality_gates (name, is_default)
SELECT 'yunq-default', true
WHERE NOT EXISTS (SELECT 1 FROM quality_gates WHERE is_default);

INSERT INTO quality_gate_conditions (gate_id, metric, operator, threshold)
SELECT g.id, c.metric, c.operator, c.threshold
FROM quality_gates g
CROSS JOIN (VALUES
    ('blocker_issues', 'gt', 0.0),
    ('critical_issues', 'gt', 0.0),
    ('parse_failures', 'gt', 0.0),
    ('coverage', 'lt', 80.0)
) AS c(metric, operator, threshold)
WHERE g.name = 'yunq-default'
  AND NOT EXISTS (SELECT 1 FROM quality_gate_conditions WHERE gate_id = g.id);
