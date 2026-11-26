-- +goose Up
-- The alert triggers (which kinds of event send an alert, and from which severity) are a third rule beside quiet hours and grouping.
-- SQLite cannot widen a CHECK in place, so the four-column table is made again with the same columns and its rows copied; nothing else
-- changes. Forward-only: there is no Down section.
ALTER TABLE notify_setting RENAME TO notify_setting_old;
CREATE TABLE notify_setting (
    key        TEXT NOT NULL PRIMARY KEY CHECK (key IN ('quiet', 'grouping', 'triggers')),
    value      TEXT NOT NULL CHECK (json_valid(value)),
    updated_at TEXT NOT NULL CHECK (updated_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    updated_by TEXT NOT NULL CHECK (length(updated_by) > 0)
);
INSERT INTO notify_setting (key, value, updated_at, updated_by) SELECT key, value, updated_at, updated_by FROM notify_setting_old;
DROP TABLE notify_setting_old;
