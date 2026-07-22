CREATE TABLE IF NOT EXISTS scan_jobs (
    id          BIGSERIAL PRIMARY KEY,
    project     TEXT        NOT NULL,
    path        TEXT        NOT NULL,
    status      TEXT        NOT NULL DEFAULT 'pending',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS scan_jobs_status_idx ON scan_jobs (status, id);
