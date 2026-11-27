-- +goose Up
-- One row per match pass: its decision coverage (M-14, coverage.go), the JSON of findings.Coverage without its time: devices, lines,
-- pairs, decided by source, undecided by cause, lines by identity method. Counts only, no device data. The newest 30 are kept.
-- Add-only: a new table, so the release stays safe to roll back. Forward-only: there is no Down section.
CREATE TABLE fnd_coverage_run (
    id     INTEGER PRIMARY KEY,
    ran_at TEXT    NOT NULL CHECK (ran_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    counts TEXT    NOT NULL CHECK (json_valid(counts) AND json_type(counts) = 'object' AND length(counts) <= 65536)
);
