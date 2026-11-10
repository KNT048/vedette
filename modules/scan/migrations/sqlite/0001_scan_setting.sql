-- +goose Up
-- Scan settings (modules/scan/CONTRACT.md INV-5, S-SCAN-2, S-SCAN-4). Forward-only (DATA_MODEL 6, rule 1).
-- One row. The database refuses what INV-5 forbids, whatever the code does; the rules that span columns
-- (from <> to, the schedule inside the window) are the service's.
CREATE TABLE scan_setting (
    id                   INTEGER NOT NULL PRIMARY KEY CHECK (id = 1),
    -- ISO weekdays, 1 = Monday ... 7 = Sunday (D-57 (9))
    days                 TEXT NOT NULL DEFAULT '[1,2,3,4,5,6,7]' CHECK (json_valid(days) AND json_type(days) = 'array' AND json_array_length(days) BETWEEN 1 AND 7),
    win_from             TEXT NOT NULL DEFAULT '22:00' CHECK (win_from GLOB '[0-2][0-9]:[0-5][0-9]' AND win_from < '24:00'),
    win_to               TEXT NOT NULL DEFAULT '05:00' CHECK (win_to GLOB '[0-2][0-9]:[0-5][0-9]' AND win_to < '24:00'),
    -- requests per second
    rate                 INTEGER NOT NULL DEFAULT 5 CHECK (rate BETWEEN 1 AND 20),
    -- IPv4 addresses or CIDR ranges
    exclusions           TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(exclusions) AND json_type(exclusions) = 'array' AND json_array_length(exclusions) <= 200),
    stop_on_unresponsive INTEGER NOT NULL DEFAULT 1 CHECK (stop_on_unresponsive IN (0, 1)),
    unresponsive_after   INTEGER NOT NULL DEFAULT 3 CHECK (unresponsive_after BETWEEN 2 AND 20),
    auto_rescan          INTEGER NOT NULL DEFAULT 1 CHECK (auto_rescan IN (0, 1)),
    sched_enabled        INTEGER NOT NULL DEFAULT 1 CHECK (sched_enabled IN (0, 1)),
    sched_frequency      TEXT NOT NULL DEFAULT 'weekly' CHECK (sched_frequency IN ('daily', 'weekly')),
    sched_weekday        INTEGER NOT NULL DEFAULT 7 CHECK (sched_weekday BETWEEN 1 AND 7),
    sched_at             TEXT NOT NULL DEFAULT '23:00' CHECK (sched_at GLOB '[0-2][0-9]:[0-5][0-9]' AND sched_at < '24:00'),
    updated_at           TEXT CHECK (updated_at IS NULL OR updated_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    updated_by           TEXT CHECK (updated_by IS NULL OR length(updated_by) BETWEEN 1 AND 320)
);

-- The defaults are those of a clean install in the mock (web/src/features/scan/mocks.ts): every day 22:00 to 05:00,
-- 5 requests per second, no exclusion, auto-stop after 3 non-responses, auto rescan on, weekly on Sunday at 23:00.
INSERT INTO scan_setting (id) VALUES (1);
