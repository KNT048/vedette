-- +goose Up
-- Automatic rescans after a new KEV entry (S-SCAN-2, CONTRACT INV-9) and the last schedule slot that ran (S-SCAN-4).
-- Forward-only (DATA_MODEL 6, rule 1).

-- One row per new KEV entry that has a scan template. result is NULL while the rescan waits or runs; the API lists
-- only rows with a result. Kept one year (DATA_MODEL [ĐX]).
CREATE TABLE scan_event (
    id          TEXT NOT NULL PRIMARY KEY CHECK (length(id) BETWEEN 1 AND 96),
    ts          TEXT NOT NULL CHECK (ts GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    cve         TEXT NOT NULL UNIQUE CHECK (cve GLOB 'CVE-[0-9][0-9][0-9][0-9]-[0-9]*' AND length(cve) <= 20),
    product     TEXT NOT NULL CHECK (length(product) <= 300),
    devices     TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(devices) AND json_type(devices) = 'array'),
    latency_min REAL CHECK (latency_min IS NULL OR latency_min >= 0),
    run_id      TEXT,
    result      TEXT CHECK (result IS NULL OR result IN ('matched', 'clear', 'skipped_off', 'no_match'))
);
CREATE INDEX scan_event_ts ON scan_event (ts);

-- The schedule slot (UTC) the last scheduled run was started for, so one slot starts at most one run.
ALTER TABLE scan_setting ADD COLUMN sched_last TEXT CHECK (sched_last IS NULL OR sched_last GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z');
