-- Quality profiles: named rule-activation sets, mirroring
-- core/profiles::QualityProfile. Structured the same way as quality_gates/
-- quality_gate_conditions (0006) rather than as an opaque JSON blob, so both
-- "quality model" entities are queryable the same way.
CREATE TABLE IF NOT EXISTS quality_profiles (
    id          BIGSERIAL   PRIMARY KEY,
    name        TEXT        NOT NULL UNIQUE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS quality_profile_activations (
    id          BIGSERIAL PRIMARY KEY,
    profile_id  BIGINT    NOT NULL REFERENCES quality_profiles(id) ON DELETE CASCADE,
    rule        TEXT      NOT NULL,
    severity    TEXT      NOT NULL
);

CREATE INDEX IF NOT EXISTS quality_profile_activations_profile_id_idx
    ON quality_profile_activations (profile_id);
CREATE UNIQUE INDEX IF NOT EXISTS quality_profile_activations_unique_rule_idx
    ON quality_profile_activations (profile_id, rule);
