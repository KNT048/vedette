-- +goose Up
-- Scan runs and the probe log (modules/scan/CONTRACT.md INV-3, INV-6, INV-7, INV-8; S-SCAN-1, S-SCAN-3, S-SCAN-4).
-- Forward-only (DATA_MODEL 6, rule 1). The per-device results are JSON in the run row (DATA_MODEL appendix A).

CREATE TABLE scan_run (
    id                TEXT NOT NULL PRIMARY KEY CHECK (length(id) BETWEEN 1 AND 96),
    trigger           TEXT NOT NULL CHECK (trigger IN ('manual', 'schedule', 'new_kev')),
    trigger_note      TEXT CHECK (trigger_note IS NULL OR length(trigger_note) BETWEEN 1 AND 300),
    started_at        TEXT NOT NULL CHECK (started_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    started_by        TEXT NOT NULL CHECK (length(started_by) BETWEEN 1 AND 320),
    ended_at          TEXT CHECK (ended_at IS NULL OR ended_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    status            TEXT NOT NULL CHECK (status IN ('running', 'stopping', 'done', 'stopped', 'auto_stopped')),
    -- picked by a person in Scan now: the pick is the consent for fragile, unclassified and hand-declared devices (D-126 (2))
    explicit          INTEGER NOT NULL CHECK (explicit IN (0, 1)),
    target_ids        TEXT NOT NULL CHECK (json_valid(target_ids) AND json_type(target_ids) = 'array' AND json_array_length(target_ids) BETWEEN 1 AND 200),
    total             INTEGER NOT NULL CHECK (total BETWEEN 1 AND 200),
    done              INTEGER NOT NULL DEFAULT 0 CHECK (done BETWEEN 0 AND total),
    -- {label, ip} of the device being scanned
    current           TEXT CHECK (current IS NULL OR (json_valid(current) AND json_type(current) = 'object')),
    -- RunResultRow[] (contract.ts)
    results           TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(results) AND json_type(results) = 'array'),
    matched           INTEGER NOT NULL DEFAULT 0 CHECK (matched >= 0),
    stop_reason       TEXT CHECK (stop_reason IS NULL OR length(stop_reason) BETWEEN 1 AND 500),
    stop_requested_at TEXT,
    CHECK ((status IN ('running', 'stopping')) = (ended_at IS NULL))
);
CREATE INDEX scan_run_started ON scan_run (started_at);
-- INV-3: one run at a time, whatever the code does
CREATE UNIQUE INDEX scan_run_one_live ON scan_run ((status IN ('running', 'stopping'))) WHERE status IN ('running', 'stopping');

-- One row per template sent to a device, written before the job leaves core (INV-7); result filled afterwards.
-- Kept 90 days (retention_days). run_id is a soft reference: the log outlives the run row.
CREATE TABLE scan_probe (
    id       TEXT NOT NULL PRIMARY KEY CHECK (length(id) BETWEEN 1 AND 96),
    ts       TEXT NOT NULL CHECK (ts GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    run_id   TEXT,
    ip       TEXT NOT NULL CHECK (length(ip) BETWEEN 1 AND 253),
    label    TEXT NOT NULL CHECK (length(label) BETWEEN 1 AND 300),
    template TEXT NOT NULL CHECK (length(template) BETWEEN 1 AND 300),
    request  TEXT NOT NULL CHECK (length(request) BETWEEN 1 AND 300),
    -- NULL while the request is on its way
    result   TEXT CHECK (result IS NULL OR result IN ('matched', 'not_matched', 'no_response', 'banner', 'stopped'))
);
CREATE INDEX scan_probe_ts ON scan_probe (ts);
CREATE INDEX scan_probe_open ON scan_probe (run_id) WHERE result IS NULL;
