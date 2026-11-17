-- +goose Up
-- #910 phase 1 (audit): one row per run of the KEV reachability audit, run after a refresh of the exploited list or of NVD's
-- affected versions (cmd/vedette job reach-audit, findings.Reachability): the feed stamp it read, the count of entries per class
-- (1 no NVD data, 2 no NVD versions, 3v keyed with a version, 3k keyed without one, 4 reached through NVD's list, 5 nothing), the
-- CVEs of each class no version comparison can reach (1, 2, 3k, 5) and those not in that class in the previous run (added). A run
-- with the stamp and classes of the previous one is not stored; the newest 30 are kept. Public feed data only, no device data.
-- Forward-only (DATA_MODEL 6, rule 1).
CREATE TABLE fnd_reach_run (
    id          INTEGER PRIMARY KEY,
    ran_at      TEXT    NOT NULL CHECK (ran_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    stamp       TEXT    NOT NULL CHECK (length(stamp) <= 4000),
    total       INTEGER NOT NULL CHECK (total >= 0),
    counts      TEXT    NOT NULL CHECK (json_valid(counts) AND json_type(counts) = 'object'),
    unreachable TEXT    NOT NULL CHECK (json_valid(unreachable) AND json_type(unreachable) = 'object'),
    added       TEXT    NOT NULL CHECK (json_valid(added) AND json_type(added) = 'object')
);
