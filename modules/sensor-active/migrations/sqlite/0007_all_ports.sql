-- +goose Up
-- D-592 (kf-scan item 1): two new LAN shapes. 'extra_ports' follows every normal or versions scan of a device (the surface list
-- and the reviewed admin ports, nmapargv.ExtraPorts); 'all_ports' is the weekly scan of every TCP port of each LAN device that is
-- not fragile (its job is of kind 'device', reason 'all_ports'). For both, sa_probe is rebuilt with the same columns and ids the way 0006 did
-- it, the AUTOINCREMENT counter going on from the old one. sa_all_ports keeps, per device, when its last weekly run was made or
-- found the device not eligible (fragile, kind unknown, never, the box: looked at again a week later), and the open ports that run
-- found outside nmapargv.ExtraPorts, so a normal scan does not drop the ones it did not find itself until the next weekly run. Forward-only (DATA_MODEL 6,
-- rule 1).
CREATE TABLE sa_all_ports (
    asset_id TEXT NOT NULL PRIMARY KEY CHECK (length(asset_id) BETWEEN 1 AND 96),
    last_at  TEXT NOT NULL CHECK (last_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    outcome  TEXT NOT NULL CHECK (outcome IN ('done', 'failed', 'not_eligible')),
    -- observe.Service[] of the open ports outside nmapargv.ExtraPorts that the last done run found
    extra    TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(extra) AND json_type(extra) = 'array' AND length(extra) <= 262144)
);

CREATE TABLE sa_probe_new (
    id           INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    time         TEXT    NOT NULL CHECK (time GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    job_id       TEXT    NOT NULL REFERENCES sa_job (id),
    shape        TEXT    NOT NULL CHECK (shape IN ('sweep', 'normal', 'gentle', 'versions', 'gentle_titles', 'snmp', 'external', 'external_full', 'external_disruptive', 'all_ports', 'extra_ports')),
    rate         INTEGER NOT NULL CHECK (rate BETWEEN 1 AND 1000),
    hosts        INTEGER NOT NULL CHECK (hosts BETWEEN 1 AND 64),
    flags        TEXT    NOT NULL CHECK (length(flags) BETWEEN 1 AND 16384),
    targets      TEXT    NOT NULL CHECK (length(targets) BETWEEN 7 AND 1100),
    result       TEXT    NOT NULL CHECK (length(result) <= 200)
);
INSERT INTO sa_probe_new (id, time, job_id, shape, rate, hosts, flags, targets, result)
    SELECT id, time, job_id, shape, rate, hosts, flags, targets, result FROM sa_probe;
INSERT INTO sqlite_sequence (name, seq)
    SELECT 'sa_probe_new', 0 WHERE NOT EXISTS (SELECT 1 FROM sqlite_sequence WHERE name = 'sa_probe_new');
UPDATE sqlite_sequence SET seq = max(seq, coalesce((SELECT seq FROM sqlite_sequence WHERE name = 'sa_probe'), 0)) WHERE name = 'sa_probe_new';

DROP TABLE sa_probe;
ALTER TABLE sa_probe_new RENAME TO sa_probe;
CREATE INDEX sa_probe_time_ix ON sa_probe (time);
CREATE INDEX sa_probe_job_ix ON sa_probe (job_id);
