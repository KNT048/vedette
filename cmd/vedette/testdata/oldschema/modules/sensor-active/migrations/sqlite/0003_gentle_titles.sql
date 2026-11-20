-- +goose Up
-- D-511 (lead decision on #714). The probe log takes the fifth command shape, "gentle_titles" (the gentle scan of a device of
-- unknown kind that nobody made fragile, plus http-title and ssl-cert on the web and TLS ports it finds open). SQLite cannot change
-- a CHECK, so the table is rebuilt with the same columns, ids, indexes and AUTOINCREMENT counter, as 0002 did. No table refers to
-- sa_probe.
-- Forward-only (DATA_MODEL 6, rule 1).
CREATE TABLE sa_probe_new (
    id           INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    time         TEXT    NOT NULL CHECK (time GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    job_id       TEXT    NOT NULL REFERENCES sa_job (id),
    shape        TEXT    NOT NULL CHECK (shape IN ('sweep', 'normal', 'gentle', 'versions', 'gentle_titles')),
    rate         INTEGER NOT NULL CHECK (rate BETWEEN 1 AND 1000),
    hosts        INTEGER NOT NULL CHECK (hosts BETWEEN 1 AND 64),
    flags        TEXT    NOT NULL CHECK (length(flags) BETWEEN 1 AND 300),
    targets      TEXT    NOT NULL CHECK (length(targets) BETWEEN 7 AND 1100),
    result       TEXT    NOT NULL CHECK (length(result) <= 200)
);
INSERT INTO sa_probe_new (id, time, job_id, shape, rate, hosts, flags, targets, result)
    SELECT id, time, job_id, shape, rate, hosts, flags, targets, result FROM sa_probe;
-- The ids of probe rows that were pruned are never handed out again (an export of the probe log is keyed by them): the new
-- table's AUTOINCREMENT counter goes on from the old one, not from the highest id left.
INSERT INTO sqlite_sequence (name, seq)
    SELECT 'sa_probe_new', 0 WHERE NOT EXISTS (SELECT 1 FROM sqlite_sequence WHERE name = 'sa_probe_new');
UPDATE sqlite_sequence SET seq = max(seq, coalesce((SELECT seq FROM sqlite_sequence WHERE name = 'sa_probe'), 0)) WHERE name = 'sa_probe_new';
DROP TABLE sa_probe;
ALTER TABLE sa_probe_new RENAME TO sa_probe;
CREATE INDEX sa_probe_time_ix ON sa_probe (time);
CREATE INDEX sa_probe_job_ix ON sa_probe (job_id);
