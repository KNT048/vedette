-- +goose Up
-- last_call_at is when the node last called the box (config, results or enrolment), written only by those calls. last_seen also serves the
-- 90-day prune, which adds the time the box or module was off to it; "quiet since" must show the real last call. Forward-only (DATA_MODEL 6).
ALTER TABLE intake_osquery_nodes ADD COLUMN last_call_at TEXT;
UPDATE intake_osquery_nodes SET last_call_at = last_seen;
