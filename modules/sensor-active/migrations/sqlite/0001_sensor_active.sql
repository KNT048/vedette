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

-- The probe log (INV-9, legal.md): one compact row per nmap run. flags is the flag part of the command line as
-- it was approved (short, no spaces inside an argument), so a later change of the templates does not rewrite
-- history; targets are the addresses it was run on as merged ranges ("a-b,c,d-e": a sweep batch skips protected
-- devices, so it has holes and first..last would not say which addresses were probed). 64 addresses always fit.
CREATE TABLE sa_probe (
    id           INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    time         TEXT    NOT NULL CHECK (time GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    job_id       TEXT    NOT NULL REFERENCES sa_job (id),
    shape        TEXT    NOT NULL CHECK (shape IN ('sweep', 'normal', 'gentle')),
    rate         INTEGER NOT NULL CHECK (rate BETWEEN 1 AND 1000),
    hosts        INTEGER NOT NULL CHECK (hosts BETWEEN 1 AND 64),
    flags        TEXT    NOT NULL CHECK (length(flags) BETWEEN 1 AND 300),
    targets      TEXT    NOT NULL CHECK (length(targets) BETWEEN 7 AND 1100),
    result       TEXT    NOT NULL CHECK (length(result) <= 200)
);
CREATE INDEX sa_probe_time_ix ON sa_probe (time);
CREATE INDEX sa_probe_job_ix ON sa_probe (job_id);

-- Where the sweep of the confirmed ranges stands (one row): the last address of the last batch finished, or
-- NULL when no pass is in progress. A window that cuts a pass is continued from here the next day; when the
-- pass reaches the end of the ranges the cursor is cleared and the next pass starts from the first address.
CREATE TABLE sa_sweep (
    id         INTEGER NOT NULL PRIMARY KEY CHECK (id = 1),
    cursor     TEXT    CHECK (cursor IS NULL OR length(cursor) BETWEEN 7 AND 15),
    updated_at TEXT    NOT NULL CHECK (updated_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z')
);

-- Devices waiting for their scan inside a window; kept here so a restart does not lose them.
CREATE TABLE sa_queue (
    asset_id  TEXT    NOT NULL PRIMARY KEY CHECK (length(asset_id) BETWEEN 1 AND 96),
    queued_at TEXT    NOT NULL CHECK (queued_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    reason    TEXT    NOT NULL CHECK (length(reason) BETWEEN 1 AND 64),
    attempts  INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0)
);
