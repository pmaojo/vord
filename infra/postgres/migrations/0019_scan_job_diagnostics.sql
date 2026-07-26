-- Failure diagnostics for the scan job queue (Fase 4, issue #30). Before
-- this, a failed job was silently released back to 'pending' forever
-- (see queue.rs's old `release`) with no attempt count and no error
-- recorded anywhere — there was nothing to diagnose a stuck or
-- perpetually-failing scan with. `attempts` counts every claim (success or
-- not); `last_error` is the most recent failure message, cleared on a
-- fresh claim; a job that exhausts its retry budget moves to the terminal
-- 'dead' status instead of being released again.
ALTER TABLE scan_jobs ADD COLUMN IF NOT EXISTS attempts INT NOT NULL DEFAULT 0;
ALTER TABLE scan_jobs ADD COLUMN IF NOT EXISTS last_error TEXT NULL;
ALTER TABLE scan_jobs ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT now();

CREATE INDEX IF NOT EXISTS scan_jobs_updated_at_idx ON scan_jobs (updated_at);
