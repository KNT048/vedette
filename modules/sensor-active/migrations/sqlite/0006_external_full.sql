-- +goose Up
-- D-526 (FULL-4): the deep scan of the box's own verified public IP once its testing terms are accepted. Its run is still a job of
-- kind 'external'; its probe row has shape 'external_full' or 'external_disruptive' (every TCP port, -sV and nmap's scripts named
-- one by one, nmapargv/scripts.go: the flags of the disruptive shape are about 7,000 characters, so flags may now be up to 16,384;
-- the probe log keeps the exact list each run was sent with). SQLite cannot change a CHECK: sa_probe is rebuilt with the same columns and ids
-- the way 0005 did it (sa_job keeps its CHECK, so it stays), and the AUTOINCREMENT counter of sa_probe goes on from the old one.
-- Every shape of 0001-0005 is kept. Forward-only (DATA_MODEL 6, rule 1).
CREATE TABLE sa_probe_new (
    id           INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    time         TEXT    NOT NULL CHECK (time GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    job_id       TEXT    NOT NULL REFERENCES sa_job (id),
    shape        TEXT    NOT NULL CHECK (shape IN ('sweep', 'normal', 'gentle', 'versions', 'gentle_titles', 'snmp', 'external', 'external_full', 'external_disruptive')),
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
