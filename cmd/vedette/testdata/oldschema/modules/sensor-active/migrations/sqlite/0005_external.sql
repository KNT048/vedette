-- +goose Up
-- D-514: service identification on the box's own verified public IP for exposure (nmap -sV, the external shape). Its run is a job
-- of kind 'external' and its probe row has shape 'external'; the row's flags hold the -p list of the 98 ports of the surface scan
-- (540 characters), so flags may now be up to 1000 characters. SQLite cannot change a CHECK: sa_job and sa_probe are rebuilt with
-- the same columns and ids, the way 0004 did it: the new sa_probe is made against the new sa_job before the old tables go, the
-- renames carry the reference (SQLite 3.26+), and the AUTOINCREMENT counter of sa_probe goes on from the old one. Every shape and
-- kind of 0001-0004 is kept (gentle_titles of 0003, snmp of 0004). Forward-only (DATA_MODEL 6, rule 1).
CREATE TABLE sa_job_new (
    id          TEXT    NOT NULL PRIMARY KEY CHECK (length(id) BETWEEN 1 AND 96),
    kind        TEXT    NOT NULL CHECK (kind IN ('sweep', 'device', 'snmp', 'external')),
    reason      TEXT    CHECK (reason IS NULL OR length(reason) <= 64),
    started_at  TEXT    NOT NULL CHECK (started_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    finished_at TEXT    CHECK (finished_at IS NULL OR finished_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    status      TEXT    NOT NULL CHECK (status IN ('running', 'done', 'stopped', 'failed')),
    targets     INTEGER NOT NULL DEFAULT 0 CHECK (targets >= 0),
    new_devices INTEGER NOT NULL DEFAULT 0 CHECK (new_devices >= 0),
    error       TEXT    CHECK (error IS NULL OR length(error) <= 1000)
);
INSERT INTO sa_job_new (id, kind, reason, started_at, finished_at, status, targets, new_devices, error)
    SELECT id, kind, reason, started_at, finished_at, status, targets, new_devices, error FROM sa_job;

CREATE TABLE sa_probe_new (
    id           INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    time         TEXT    NOT NULL CHECK (time GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    job_id       TEXT    NOT NULL REFERENCES sa_job_new (id),
    shape        TEXT    NOT NULL CHECK (shape IN ('sweep', 'normal', 'gentle', 'versions', 'gentle_titles', 'snmp', 'external')),
    rate         INTEGER NOT NULL CHECK (rate BETWEEN 1 AND 1000),
    hosts        INTEGER NOT NULL CHECK (hosts BETWEEN 1 AND 64),
    flags        TEXT    NOT NULL CHECK (length(flags) BETWEEN 1 AND 1000),
    targets      TEXT    NOT NULL CHECK (length(targets) BETWEEN 7 AND 1100),
    result       TEXT    NOT NULL CHECK (length(result) <= 200)
);
INSERT INTO sa_probe_new (id, time, job_id, shape, rate, hosts, flags, targets, result)
    SELECT id, time, job_id, shape, rate, hosts, flags, targets, result FROM sa_probe;
INSERT INTO sqlite_sequence (name, seq)
    SELECT 'sa_probe_new', 0 WHERE NOT EXISTS (SELECT 1 FROM sqlite_sequence WHERE name = 'sa_probe_new');
UPDATE sqlite_sequence SET seq = max(seq, coalesce((SELECT seq FROM sqlite_sequence WHERE name = 'sa_probe'), 0)) WHERE name = 'sa_probe_new';

DROP TABLE sa_probe;
DROP TABLE sa_job;
ALTER TABLE sa_job_new RENAME TO sa_job;
ALTER TABLE sa_probe_new RENAME TO sa_probe;
CREATE INDEX sa_job_started_ix ON sa_job (kind, started_at);
CREATE INDEX sa_probe_time_ix ON sa_probe (time);
CREATE INDEX sa_probe_job_ix ON sa_probe (job_id);
