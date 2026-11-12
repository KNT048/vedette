-- +goose Up
-- A finding whose device no longer matches its entry says so in its history (D-439): two new actions (no_longer_matches, matches_again). SQLite cannot change a
-- CHECK, so the table is rebuilt with the same columns, index and trigger. Forward-only (DATA_MODEL 6, rule 1).
CREATE TABLE fnd_finding_history_new (
    id         TEXT NOT NULL PRIMARY KEY CHECK (length(id) BETWEEN 1 AND 96),
    finding_id TEXT NOT NULL REFERENCES fnd_finding (id) ON DELETE CASCADE,
    ts         TEXT NOT NULL CHECK (ts GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    user       TEXT NOT NULL CHECK (length(user) BETWEEN 1 AND 320),
    action     TEXT NOT NULL CHECK (action IN ('created', 'confirmed', 'rescanned', 'rescan_clear', 'no_longer_matches', 'matches_again', 'reopened', 'patched', 'mitigated', 'false_positive', 'not_relevant')),
    note       TEXT CHECK (note IS NULL OR length(note) <= 600)
);
INSERT INTO fnd_finding_history_new (id, finding_id, ts, user, action, note)
    SELECT id, finding_id, ts, user, action, note FROM fnd_finding_history;
DROP TABLE fnd_finding_history;
ALTER TABLE fnd_finding_history_new RENAME TO fnd_finding_history;
CREATE INDEX fnd_finding_history_finding_idx ON fnd_finding_history (finding_id, ts);

-- +goose StatementBegin
CREATE TRIGGER fnd_finding_history_no_update BEFORE UPDATE ON fnd_finding_history
BEGIN
    SELECT RAISE(ABORT, 'fnd_finding_history is append-only');
END;
-- +goose StatementEnd
