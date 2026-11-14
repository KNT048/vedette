-- +goose Up
-- D-523: the normal and versions shapes name their ports with -p (nmap 7.95's top 1000 plus the surface scan's list, written as
-- ranges, about 4,000 characters) instead of --top-ports 1000, and the probe row keeps the flags exactly as checked (INV-9), so
-- flags may now be up to 6000 characters. SQLite cannot change a CHECK: sa_probe is rebuilt with the same columns and ids, the
-- way 0005 did it; sa_job is unchanged and the new table references it by name. The AUTOINCREMENT counter goes on from the old
-- one. Forward-only (DATA_MODEL 6, rule 1).
CREATE TABLE sa_probe_new (
    id           INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    time         TEXT    NOT NULL CHECK (time GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    job_id       TEXT    NOT NULL REFERENCES sa_job (id),
    shape        TEXT    NOT NULL CHECK (shape IN ('sweep', 'normal', 'gentle', 'versions', 'gentle_titles', 'snmp', 'external')),
    rate         INTEGER NOT NULL CHECK (rate BETWEEN 1 AND 1000),
    hosts        INTEGER NOT NULL CHECK (hosts BETWEEN 1 AND 64),
    flags        TEXT    NOT NULL CHECK (length(flags) BETWEEN 1 AND 6000),
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
