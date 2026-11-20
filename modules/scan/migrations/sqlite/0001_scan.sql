-- +goose Up
-- The whole schema of the scan module. It is edited in place until the first public release; docs/SCHEMA.sql
-- shows the schema of every module together. Forward-only: there is no Down section.

CREATE TABLE scan_setting (
    id                   INTEGER NOT NULL PRIMARY KEY CHECK (id = 1),
    -- ISO weekdays, 1 = Monday ... 7 = Sunday (D-57 (9))
    days                 TEXT NOT NULL DEFAULT '[1,2,3,4,5,6,7]' CHECK (json_valid(days) AND json_type(days) = 'array' AND json_array_length(days) BETWEEN 1 AND 7),
    win_from             TEXT NOT NULL DEFAULT '22:00' CHECK (win_from GLOB '[0-2][0-9]:[0-5][0-9]' AND win_from < '24:00'),
    win_to               TEXT NOT NULL DEFAULT '05:00' CHECK (win_to GLOB '[0-2][0-9]:[0-5][0-9]' AND win_to < '24:00'),
    -- requests per second
    rate                 INTEGER NOT NULL DEFAULT 5 CHECK (rate BETWEEN 1 AND 20),
    -- IPv4 addresses or CIDR ranges
    exclusions           TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(exclusions) AND json_type(exclusions) = 'array' AND json_array_length(exclusions) <= 200),
    stop_on_unresponsive INTEGER NOT NULL DEFAULT 1 CHECK (stop_on_unresponsive IN (0, 1)),
    unresponsive_after   INTEGER NOT NULL DEFAULT 3 CHECK (unresponsive_after BETWEEN 2 AND 20),
    auto_rescan          INTEGER NOT NULL DEFAULT 1 CHECK (auto_rescan IN (0, 1)),
    sched_enabled        INTEGER NOT NULL DEFAULT 1 CHECK (sched_enabled IN (0, 1)),
    sched_frequency      TEXT NOT NULL DEFAULT 'weekly' CHECK (sched_frequency IN ('daily', 'weekly')),
    sched_weekday        INTEGER NOT NULL DEFAULT 7 CHECK (sched_weekday BETWEEN 1 AND 7),
    sched_at             TEXT NOT NULL DEFAULT '23:00' CHECK (sched_at GLOB '[0-2][0-9]:[0-5][0-9]' AND sched_at < '24:00'),
    updated_at           TEXT CHECK (updated_at IS NULL OR updated_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    updated_by           TEXT CHECK (updated_by IS NULL OR length(updated_by) BETWEEN 1 AND 320)
, sched_last TEXT CHECK (sched_last IS NULL OR sched_last GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'), kev_read_at TEXT CHECK (kev_read_at IS NULL OR kev_read_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'), kev_read_cve TEXT NOT NULL DEFAULT '' CHECK (length(kev_read_cve) <= 64));

CREATE TABLE scan_run (
    id                TEXT NOT NULL PRIMARY KEY CHECK (length(id) BETWEEN 1 AND 96),
    trigger           TEXT NOT NULL CHECK (trigger IN ('manual', 'schedule', 'new_kev')),
    trigger_note      TEXT CHECK (trigger_note IS NULL OR length(trigger_note) BETWEEN 1 AND 300),
    started_at        TEXT NOT NULL CHECK (started_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    started_by        TEXT NOT NULL CHECK (length(started_by) BETWEEN 1 AND 320),
    ended_at          TEXT CHECK (ended_at IS NULL OR ended_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    status            TEXT NOT NULL CHECK (status IN ('running', 'stopping', 'done', 'stopped', 'auto_stopped')),
    -- the ids a person picked in Scan now that needed the pick (pick_only when the run started): the consent of D-126 (2),
    -- per device; every other device of the run is checked again without it
    picked            TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(picked) AND json_type(picked) = 'array'),
    target_ids        TEXT NOT NULL CHECK (json_valid(target_ids) AND json_type(target_ids) = 'array' AND json_array_length(target_ids) BETWEEN 1 AND 200),
    total             INTEGER NOT NULL CHECK (total BETWEEN 1 AND 200),
    done              INTEGER NOT NULL DEFAULT 0 CHECK (done BETWEEN 0 AND total),
    -- {label, ip} of the device being scanned
    current           TEXT CHECK (current IS NULL OR (json_valid(current) AND json_type(current) = 'object')),
    -- RunResultRow[] (contract.ts)
    results           TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(results) AND json_type(results) = 'array'),
    matched           INTEGER NOT NULL DEFAULT 0 CHECK (matched >= 0),
    stop_reason       TEXT CHECK (stop_reason IS NULL OR length(stop_reason) BETWEEN 1 AND 500),
    stop_requested_at TEXT, identification TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(identification) AND json_type(identification) = 'array'),
    CHECK ((status IN ('running', 'stopping')) = (ended_at IS NULL))
);

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
    run_id   TEXT,
    ip       TEXT NOT NULL CHECK (length(ip) BETWEEN 1 AND 253),
    label    TEXT NOT NULL CHECK (length(label) BETWEEN 1 AND 300),
    template TEXT NOT NULL CHECK (length(template) BETWEEN 1 AND 300),
    request  TEXT NOT NULL CHECK (length(request) BETWEEN 1 AND 300),
    -- NULL while the request is on its way
    result   TEXT CHECK (result IS NULL OR result IN ('matched', 'not_matched', 'no_response', 'banner', 'stopped', 'not_run', 'refused'))
);

CREATE INDEX scan_run_started ON scan_run (started_at);

-- INV-3: one run at a time, whatever the code does
CREATE UNIQUE INDEX scan_run_one_live ON scan_run ((status IN ('running', 'stopping'))) WHERE status IN ('running', 'stopping');

CREATE INDEX scan_event_ts ON scan_event (ts);

CREATE INDEX scan_probe_ts ON scan_probe (ts);

CREATE INDEX scan_probe_open ON scan_probe (run_id) WHERE result IS NULL;

INSERT INTO scan_setting (id) VALUES (1);
