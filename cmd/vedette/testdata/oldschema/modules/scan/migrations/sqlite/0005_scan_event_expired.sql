-- +goose Up
-- A KEV rescan dropped after 7 days stays in the log with the reason (S-SCAN-2, D-261 (2)): three new results. SQLite
-- cannot change a CHECK, so the table is rebuilt with the same columns. Forward-only (DATA_MODEL 6, rule 1).
CREATE TABLE scan_event_new (
    id          TEXT NOT NULL PRIMARY KEY CHECK (length(id) BETWEEN 1 AND 96),
    ts          TEXT NOT NULL CHECK (ts GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    cve         TEXT NOT NULL UNIQUE CHECK (cve GLOB 'CVE-[0-9][0-9][0-9][0-9]-[0-9]*' AND length(cve) <= 20),
    product     TEXT NOT NULL CHECK (length(product) <= 300),
    devices     TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(devices) AND json_type(devices) = 'array'),
    latency_min REAL CHECK (latency_min IS NULL OR latency_min >= 0),
    run_id      TEXT,
    result      TEXT CHECK (result IS NULL OR result IN ('matched', 'clear', 'skipped_off', 'no_match', 'pick_only', 'stopped', 'expired_no_template', 'expired_scanner', 'expired_zone'))
);
INSERT INTO scan_event_new (id, ts, cve, product, devices, latency_min, run_id, result)
    SELECT id, ts, cve, product, devices, latency_min, run_id, result FROM scan_event;
DROP TABLE scan_event;
ALTER TABLE scan_event_new RENAME TO scan_event;
CREATE INDEX scan_event_ts ON scan_event (ts);
