-- +goose NO TRANSACTION
-- +goose Up
-- D-498: a person accepts the risk of a finding until a day (status risk_accepted, column accepted_until 'YYYY-MM-DD', history
-- action risk_accepted). SQLite cannot change a CHECK, so fnd_finding and fnd_finding_history are rebuilt with the same columns,
-- ids, indexes and trigger. fnd_finding is the parent of ON DELETE CASCADE keys (fnd_finding_history, mit_applied,
-- mit_ai_output): with foreign keys on, DROP TABLE fnd_finding would delete every child row. So this migration runs outside
-- goose's transaction, turns foreign keys off on its own connection and makes its own transaction, the documented SQLite
-- procedure (https://www.sqlite.org/lang_altertable.html#otheralter). The children keep "REFERENCES fnd_finding" and point at the
-- new table once it has the name. Forward-only (DATA_MODEL 6, rule 1).
PRAGMA foreign_keys = OFF;

BEGIN IMMEDIATE;

DROP TABLE IF EXISTS fnd_finding_new;
CREATE TABLE fnd_finding_new (
    id                TEXT    NOT NULL PRIMARY KEY CHECK (length(id) BETWEEN 1 AND 96),
    asset_id          TEXT    NOT NULL CHECK (length(asset_id) BETWEEN 1 AND 96),
    cve               TEXT    NOT NULL
        CHECK (cve GLOB 'CVE-[0-9][0-9][0-9][0-9]-[0-9][0-9][0-9][0-9]*'
               AND substr(cve, 5) NOT GLOB '*[^0-9-]*'
               AND cve NOT GLOB 'CVE-[0-9][0-9][0-9][0-9]-*-*'),
    status            TEXT    NOT NULL CHECK (status IN ('confirmed', 'suspected', 'mitigated', 'patched', 'false_positive', 'not_relevant', 'risk_accepted')),
    severity          TEXT    NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
    confidence        REAL    NOT NULL CHECK (confidence >= 0 AND confidence <= 1),
    basis             TEXT    NOT NULL CHECK (basis IN ('scan', 'version', 'product')),
    evidence          TEXT    CHECK (evidence IS NULL OR (json_valid(evidence) AND json_type(evidence) = 'object')),
    first_seen        TEXT    NOT NULL CHECK (first_seen GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    last_seen         TEXT    NOT NULL CHECK (last_seen GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    resolved_by       TEXT    CHECK (resolved_by IS NULL OR length(resolved_by) BETWEEN 1 AND 320),
    resolved_at       TEXT    CHECK (resolved_at IS NULL OR resolved_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    resolution_note   TEXT    CHECK (resolution_note IS NULL OR length(resolution_note) <= 500),
    resolution_reason TEXT    CHECK (resolution_reason IS NULL OR resolution_reason IN ('not_affected_version')),
    -- D-498: the last day of a risk acceptance (UTC); set exactly while the status is risk_accepted.
    accepted_until    TEXT    CHECK (accepted_until IS NULL OR accepted_until GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]'),
    CHECK (status <> 'confirmed' OR (basis = 'scan' AND evidence IS NOT NULL)),
    CHECK ((status = 'risk_accepted') = (accepted_until IS NOT NULL)),
    UNIQUE (asset_id, cve)
);
INSERT INTO fnd_finding_new (id, asset_id, cve, status, severity, confidence, basis, evidence, first_seen, last_seen, resolved_by, resolved_at, resolution_note, resolution_reason)
    SELECT id, asset_id, cve, status, severity, confidence, basis, evidence, first_seen, last_seen, resolved_by, resolved_at, resolution_note, resolution_reason FROM fnd_finding ORDER BY rowid;
DROP TABLE fnd_finding;
ALTER TABLE fnd_finding_new RENAME TO fnd_finding;
CREATE INDEX fnd_finding_status_idx ON fnd_finding (status);
CREATE INDEX fnd_finding_cve_idx ON fnd_finding (cve);
CREATE INDEX fnd_finding_asset_status_idx ON fnd_finding (asset_id, status);

DROP TABLE IF EXISTS fnd_finding_history_new;
CREATE TABLE fnd_finding_history_new (
    id         TEXT NOT NULL PRIMARY KEY CHECK (length(id) BETWEEN 1 AND 96),
    finding_id TEXT NOT NULL REFERENCES fnd_finding (id) ON DELETE CASCADE,
    ts         TEXT NOT NULL CHECK (ts GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    user       TEXT NOT NULL CHECK (length(user) BETWEEN 1 AND 320),
    action     TEXT NOT NULL CHECK (action IN ('created', 'confirmed', 'rescanned', 'rescan_clear', 'no_longer_matches', 'matches_again', 'reopened', 'patched', 'mitigated', 'false_positive', 'not_relevant', 'risk_accepted')),
    note       TEXT CHECK (note IS NULL OR length(note) <= 600)
);
INSERT INTO fnd_finding_history_new (id, finding_id, ts, user, action, note)
    SELECT id, finding_id, ts, user, action, note FROM fnd_finding_history ORDER BY rowid;
DROP TABLE fnd_finding_history;
ALTER TABLE fnd_finding_history_new RENAME TO fnd_finding_history;
CREATE INDEX fnd_finding_history_finding_idx ON fnd_finding_history (finding_id, ts);

-- +goose StatementBegin
CREATE TRIGGER fnd_finding_history_no_update BEFORE UPDATE ON fnd_finding_history
BEGIN
    SELECT RAISE(ABORT, 'fnd_finding_history is append-only');
END;
-- +goose StatementEnd

COMMIT;

PRAGMA foreign_keys = ON;
