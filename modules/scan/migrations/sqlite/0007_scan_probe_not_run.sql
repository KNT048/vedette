-- +goose Up
-- Two results of the probe log (INV-7; kf-scan item 5, N44-4 review r1 M1): not_run (a template handed to nuclei that nuclei did
-- not run: a finished run printed no line for it) and refused (the scan worker's own-IP fence refused the job, nothing was sent).
-- SQLite cannot change a CHECK, so the table is rebuilt with the same columns, rowids kept (the CSV and the page order by rowid).
-- Forward-only (DATA_MODEL 6, rule 1).
CREATE TABLE scan_probe_new (
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
INSERT INTO scan_probe_new (rowid, id, ts, run_id, ip, label, template, request, result)
    SELECT rowid, id, ts, run_id, ip, label, template, request, result FROM scan_probe;
DROP TABLE scan_probe;
ALTER TABLE scan_probe_new RENAME TO scan_probe;
CREATE INDEX scan_probe_ts ON scan_probe (ts);
CREATE INDEX scan_probe_open ON scan_probe (run_id) WHERE result IS NULL;
