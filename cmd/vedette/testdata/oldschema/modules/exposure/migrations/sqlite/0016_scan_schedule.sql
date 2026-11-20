-- +goose Up
-- A scan schedule per target (CONTRACT INV-36): off, daily, weekly or monthly. Every target, those that exist now included, starts
-- weekly. The next scheduled scan is computed from the start of the newest scan (last_scan_at), so it survives a restart.
-- sched_skip is why the last due scheduled scan was not run (the target page says it), sched_skip_at when that was decided, and
-- sched_retry_at the earliest time the schedule tries again after a skip the scan gate decided (the TXT record or the proof not found
-- right before the scan, the box no longer going out through the IP, the address on the exclusion list). Forward-only (DATA_MODEL 6,
-- rule 1).
ALTER TABLE exp_target ADD COLUMN scan_every TEXT NOT NULL DEFAULT 'weekly' CHECK (scan_every IN ('off', 'daily', 'weekly', 'monthly'));
ALTER TABLE exp_target ADD COLUMN sched_skip TEXT CHECK (sched_skip IS NULL OR length(sched_skip) BETWEEN 1 AND 1000);
ALTER TABLE exp_target ADD COLUMN sched_skip_at TEXT CHECK ((sched_skip_at IS NULL) = (sched_skip IS NULL) AND (sched_skip_at IS NULL OR sched_skip_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'));
ALTER TABLE exp_target ADD COLUMN sched_retry_at TEXT CHECK (sched_retry_at IS NULL OR (sched_skip IS NOT NULL AND sched_retry_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'));
