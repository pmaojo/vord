CREATE TABLE IF NOT EXISTS hotspots (
    id          BIGSERIAL PRIMARY KEY,
    rule        TEXT        NOT NULL,
    message     TEXT        NOT NULL,
    file        TEXT        NOT NULL,
    start_line  INTEGER     NOT NULL,
    start_col   INTEGER     NOT NULL,
    end_line    INTEGER     NOT NULL,
    end_col     INTEGER     NOT NULL,
    status      TEXT        NOT NULL DEFAULT 'to-review',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS hotspots_status_idx ON hotspots (status);
