-- +goose Up
-- Active discovery tables (docs/DATA_MODEL.md 4.14). Forward-only (DATA_MODEL 6, rule 1): no Down section.
-- Only sensoractive.Service writes these tables. sa_snmp is not created: SNMP is not built (D-84 (3)).

-- One run of nmap work: a sweep of the confirmed ranges, or the scan of one device.
CREATE TABLE sa_job (
    id          TEXT    NOT NULL PRIMARY KEY CHECK (length(id) BETWEEN 1 AND 96),
    kind        TEXT    NOT NULL CHECK (kind IN ('sweep', 'device')),
    reason      TEXT    CHECK (reason IS NULL OR length(reason) <= 64),
    started_at  TEXT    NOT NULL CHECK (started_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    finished_at TEXT    CHECK (finished_at IS NULL OR finished_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    status      TEXT    NOT NULL CHECK (status IN ('running', 'done', 'stopped', 'failed')),
    targets     INTEGER NOT NULL DEFAULT 0 CHECK (targets >= 0),
    new_devices INTEGER NOT NULL DEFAULT 0 CHECK (new_devices >= 0),
    error       TEXT    CHECK (error IS NULL OR length(error) <= 1000)
);
CREATE INDEX sa_job_started_ix ON sa_job (kind, started_at);

-- The probe log (INV-9, legal.md): one row per nmap run, with the argv exactly as it was approved.
CREATE TABLE sa_probe (
    id     INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    time   TEXT    NOT NULL CHECK (time GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    target TEXT    NOT NULL CHECK (length(target) BETWEEN 1 AND 200),
    argv   TEXT    NOT NULL CHECK (json_valid(argv) AND json_type(argv) = 'array'),
    result TEXT    NOT NULL CHECK (length(result) <= 200),
    job_id TEXT    NOT NULL REFERENCES sa_job (id)
);
CREATE INDEX sa_probe_time_ix ON sa_probe (time);

-- Devices waiting for their scan inside a window; kept here so a restart does not lose them.
CREATE TABLE sa_queue (
    asset_id  TEXT    NOT NULL PRIMARY KEY CHECK (length(asset_id) BETWEEN 1 AND 96),
    queued_at TEXT    NOT NULL CHECK (queued_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    reason    TEXT    NOT NULL CHECK (length(reason) BETWEEN 1 AND 64),
    attempts  INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0)
);
