-- +goose Up
-- N49-3, N49-2 (D-595): the state of a snapshot's OpenVAS step (running, done, partial, not_run, failed, stopped) and when it started
-- (RFC 3339 UTC), as one JSON object: the page's OpenVAS heading follows it and shows the start in the viewer's time zone. A snapshot
-- taken before this version has '{}', read as the state its lines say (storedGreenboneRun). Forward-only (DATA_MODEL 6, rule 1).
ALTER TABLE exp_snapshot ADD COLUMN greenbone_run TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(greenbone_run) AND json_type(greenbone_run) = 'object');
