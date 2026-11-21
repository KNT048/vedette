-- +goose Up
-- The whole schema of the scan module. It is edited in place until the first public release; docs/SCHEMA.sql
-- shows the schema of every module together. Forward-only: there is no Down section.
-- A vulnerability check is a core_run (kind vuln_check) with its steps and items; this module keeps only what is its own:
-- the settings of the checks (when they run is a core_schedule row, scan.vuln), the log of automatic rescans and the probe log, keyed by the run.

CREATE TABLE scan_setting (
    id                   INTEGER NOT NULL PRIMARY KEY CHECK (id = 1),
    stop_on_unresponsive INTEGER NOT NULL DEFAULT 1 CHECK (stop_on_unresponsive IN (0, 1)),
    unresponsive_after   INTEGER NOT NULL DEFAULT 3 CHECK (unresponsive_after BETWEEN 2 AND 20),
    auto_rescan          INTEGER NOT NULL DEFAULT 1 CHECK (auto_rescan IN (0, 1)),
    updated_at           TEXT CHECK (updated_at IS NULL OR updated_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    updated_by           TEXT CHECK (updated_by IS NULL OR length(updated_by) BETWEEN 1 AND 320),
    kev_read_at TEXT CHECK (kev_read_at IS NULL OR kev_read_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'), kev_read_cve TEXT NOT NULL DEFAULT '' CHECK (length(kev_read_cve) <= 64));

CREATE TABLE "scan_event" (
    id          TEXT NOT NULL PRIMARY KEY CHECK (length(id) BETWEEN 1 AND 96),
    ts          TEXT NOT NULL CHECK (ts GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    cve         TEXT NOT NULL UNIQUE CHECK (cve GLOB 'CVE-[0-9][0-9][0-9][0-9]-[0-9]*' AND length(cve) <= 20),
    product     TEXT NOT NULL CHECK (length(product) <= 300),
    devices     TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(devices) AND json_type(devices) = 'array'),
    latency_min REAL CHECK (latency_min IS NULL OR latency_min >= 0),
    run_id      TEXT,
    result      TEXT CHECK (result IS NULL OR result IN ('matched', 'clear', 'skipped_off', 'no_match', 'pick_only', 'stopped', 'expired_no_template', 'expired_scanner', 'expired_zone'))
);

CREATE TABLE "scan_probe" (
    id       TEXT NOT NULL PRIMARY KEY CHECK (length(id) BETWEEN 1 AND 96),
    ts       TEXT NOT NULL CHECK (ts GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    -- NULL for the probes of an external-surface scan, and once the run is deleted
    run_id   TEXT REFERENCES core_run (id) ON DELETE SET NULL,
    ip       TEXT NOT NULL CHECK (length(ip) BETWEEN 1 AND 253),
    label    TEXT NOT NULL CHECK (length(label) BETWEEN 1 AND 300),
    template TEXT NOT NULL CHECK (length(template) BETWEEN 1 AND 300),
    request  TEXT NOT NULL CHECK (length(request) BETWEEN 1 AND 300),
    -- NULL while the request is on its way
    result   TEXT CHECK (result IS NULL OR result IN ('matched', 'not_matched', 'no_response', 'banner', 'stopped', 'not_run', 'refused'))
);

CREATE INDEX scan_event_ts ON scan_event (ts);

CREATE INDEX scan_probe_ts ON scan_probe (ts);

CREATE INDEX scan_probe_open ON scan_probe (run_id) WHERE result IS NULL;

INSERT INTO scan_setting (id) VALUES (1);
