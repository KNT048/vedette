-- +goose NO TRANSACTION
-- +goose Up
-- A version the device itself states confirms a finding: status confirmed now also allows basis version when the evidence says the
-- device stated the version (evidence.source 'snmp': its answer to Vedette's SNMP read with its community; 'agent': its own agent's OS
-- or package list). SQLite cannot change a CHECK, so fnd_finding is rebuilt with the same columns and indexes, the way migrations
-- 0005 and 0013 do it: outside goose's transaction, foreign keys off on this connection, so the ON DELETE CASCADE children
-- (history, not-installed marks, applied mitigations, AI output) keep their rows and point at the new table once it has the name.
-- The history table is not touched (its actions are unchanged). Forward-only (DATA_MODEL 6, rule 1).
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
    basis             TEXT    NOT NULL CHECK (basis IN ('scan', 'version', 'product', 'person')),
    evidence          TEXT    CHECK (evidence IS NULL OR (json_valid(evidence) AND json_type(evidence) = 'object')),
    first_seen        TEXT    NOT NULL CHECK (first_seen GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    last_seen         TEXT    NOT NULL CHECK (last_seen GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    resolved_by       TEXT    CHECK (resolved_by IS NULL OR length(resolved_by) BETWEEN 1 AND 320),
    resolved_at       TEXT    CHECK (resolved_at IS NULL OR resolved_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    resolution_note   TEXT    CHECK (resolution_note IS NULL OR length(resolution_note) <= 500),
    resolution_reason TEXT    CHECK (resolution_reason IS NULL OR resolution_reason IN ('not_affected_version')),
    -- The last day of a risk acceptance (UTC); set exactly while the status is risk_accepted.
    accepted_until    TEXT    CHECK (accepted_until IS NULL OR accepted_until GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]'),
    software_id       TEXT    CHECK (software_id IS NULL OR length(software_id) BETWEEN 1 AND 200),
    proved_version    TEXT    CHECK (proved_version IS NULL OR length(proved_version) BETWEEN 1 AND 200),
    -- confirmed: a scan or a person, or a version the device itself stated (its SNMP answer or its own agent) inside an affected
    -- range with an end: basis version and the evidence's source says so.
    CHECK (status <> 'confirmed' OR (evidence IS NOT NULL AND (basis IN ('scan', 'person')
        OR (basis = 'version' AND coalesce(json_extract(evidence, '$.source'), '') IN ('snmp', 'agent'))))),
    CHECK ((status = 'risk_accepted') = (accepted_until IS NOT NULL)),
    UNIQUE (asset_id, cve)
);
INSERT INTO fnd_finding_new (id, asset_id, cve, status, severity, confidence, basis, evidence, first_seen, last_seen, resolved_by, resolved_at, resolution_note, resolution_reason, accepted_until, software_id, proved_version)
    SELECT id, asset_id, cve, status, severity, confidence, basis, evidence, first_seen, last_seen, resolved_by, resolved_at, resolution_note, resolution_reason, accepted_until, software_id, proved_version FROM fnd_finding ORDER BY rowid;
DROP TABLE fnd_finding;
ALTER TABLE fnd_finding_new RENAME TO fnd_finding;
CREATE INDEX fnd_finding_status_idx ON fnd_finding (status);
CREATE INDEX fnd_finding_cve_idx ON fnd_finding (cve);
CREATE INDEX fnd_finding_asset_status_idx ON fnd_finding (asset_id, status);
CREATE INDEX fnd_finding_status_resolved_idx ON fnd_finding (status, resolved_at);

COMMIT;

PRAGMA foreign_keys = ON;
