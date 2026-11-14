-- +goose Up
-- D-592 (kf-scan item 1, review r1): three new LAN shapes. 'extra_ports' follows every normal or versions scan of a device (the
-- surface list and the reviewed admin ports, nmapargv.ExtraPorts); 'all_ports' is the weekly port discovery over every TCP port of
-- each LAN device that is not fragile (its job is of kind 'device', reason 'all_ports'); 'port_versions' is its -sV follow-up on
-- at most 20 of the ports it found. For them sa_probe is rebuilt with the same columns and ids the way 0006 did it, the
-- AUTOINCREMENT counter going on from the old one. sa_all_ports keeps, per device: when its last weekly run was made or found the
-- device not eligible (fragile, kind unknown, never, the box: looked at again a week later; NULL: never); the open ports a normal
-- scan found (the follow-up does not read them again); and the open ports the last done weekly run found outside
-- nmapargv.ExtraPorts with that run's time, so a normal scan keeps the ones it does not find itself until the next weekly run, 14
-- days at most. Rows of devices the inventory no longer has are removed by the weekly round. Forward-only (DATA_MODEL 6, rule 1).
CREATE TABLE sa_all_ports (
    asset_id     TEXT NOT NULL PRIMARY KEY CHECK (length(asset_id) BETWEEN 1 AND 96),
    last_at      TEXT CHECK (last_at IS NULL OR last_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    outcome      TEXT CHECK (outcome IS NULL OR outcome IN ('done', 'not_eligible')),
    -- observe.Service[] of the open ports outside nmapargv.ExtraPorts that the last done weekly run found, at extra_at
    extra        TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(extra) AND json_type(extra) = 'array' AND length(extra) <= 262144),
    extra_at     TEXT CHECK (extra_at IS NULL OR extra_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    -- the TCP ports the last normal or versions scan found open
    normal_ports TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(normal_ports) AND json_type(normal_ports) = 'array' AND length(normal_ports) <= 16384)
);

CREATE TABLE sa_probe_new (
    id           INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    time         TEXT    NOT NULL CHECK (time GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    job_id       TEXT    NOT NULL REFERENCES sa_job (id),
    shape        TEXT    NOT NULL CHECK (shape IN ('sweep', 'normal', 'gentle', 'versions', 'gentle_titles', 'snmp', 'external', 'external_full', 'external_disruptive', 'all_ports', 'extra_ports', 'port_versions')),
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
