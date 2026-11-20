-- +goose Up
-- Reports (modules/reports/CONTRACT.md). Forward-only. Four tables, prefix rep_ (MANIFEST).

-- The weekly send schedule: one row (id = 1), made on first save. recipients is a JSON array of at most 20 addresses.
-- armed_at is when the schedule was last saved: a slot before it never counts as missed (a new schedule does not send for last
-- Monday). last_slot_at is the slot the job last sent or skipped, so each slot is handled once (at most once, POST-2).
CREATE TABLE rep_schedule (
    id           INTEGER NOT NULL PRIMARY KEY CHECK (id = 1),
    enabled      INTEGER NOT NULL CHECK (enabled IN (0, 1)),
    zone         TEXT NOT NULL CHECK (length(zone) BETWEEN 1 AND 64), -- the box time zone the slots were computed in
    day          INTEGER NOT NULL CHECK (day BETWEEN 1 AND 7),
    hour         INTEGER NOT NULL CHECK (hour BETWEEN 0 AND 23),
    recipients   TEXT NOT NULL CHECK (json_valid(recipients) AND json_type(recipients) = 'array' AND json_array_length(recipients) <= 20),
    armed_at     TEXT NOT NULL,
    last_slot_at TEXT
);

-- One row per send attempt; report holds the figures of that week as they were (INV-2), never recomputed.
CREATE TABLE rep_history (
    id         TEXT NOT NULL PRIMARY KEY CHECK (length(id) BETWEEN 1 AND 96),
    ts         TEXT NOT NULL,
    trigger    TEXT NOT NULL CHECK (trigger IN ('manual', 'scheduled')),
    recipients TEXT NOT NULL CHECK (json_valid(recipients) AND json_type(recipients) = 'array'),
    status     TEXT NOT NULL CHECK (status IN ('sent', 'failed')),
    error      TEXT CHECK (error IS NULL OR length(error) <= 500),
    report     TEXT NOT NULL CHECK (json_valid(report) AND json_type(report) = 'object')
);
CREATE INDEX rep_history_ts ON rep_history (ts DESC);

-- The last AI commentary on the weekly report: one row (id = 1).
CREATE TABLE rep_weekly_ai (
    id      INTEGER NOT NULL PRIMARY KEY CHECK (id = 1),
    summary TEXT NOT NULL CHECK (json_valid(summary) AND json_type(summary) = 'object')
);

-- The personal-data-protection self-assessment: the organisation's details and the last generated report; one row (id = 1).
CREATE TABLE rep_pdpl (
    id     INTEGER NOT NULL PRIMARY KEY CHECK (id = 1),
    org    TEXT CHECK (org IS NULL OR (json_valid(org) AND json_type(org) = 'object')),
    report TEXT CHECK (report IS NULL OR (json_valid(report) AND json_type(report) = 'object'))
);
