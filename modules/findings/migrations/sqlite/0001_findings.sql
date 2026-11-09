-- +goose Up
-- Findings (docs/DATA_MODEL.md 4.3, modules/findings/CONTRACT.md). Forward-only (DATA_MODEL 6, rule 1).

-- One row per (device, CVE) pair (INV-1). asset_id has NO foreign key: inv_asset belongs to the
-- inventory module, which is not built yet and may not be on. Deleting a device deletes its findings
-- through the findings.Service.OnAssetDeleted handler of the inventory.asset.deleted event (INV-7), not
-- through ON DELETE CASCADE. When inventory lands, adding the FK is a new migration of this module.
CREATE TABLE fnd_finding (
    id              TEXT    NOT NULL PRIMARY KEY CHECK (length(id) BETWEEN 1 AND 96),
    asset_id        TEXT    NOT NULL CHECK (length(asset_id) BETWEEN 1 AND 96),
    cve             TEXT    NOT NULL
        CHECK (cve GLOB 'CVE-[0-9][0-9][0-9][0-9]-[0-9][0-9][0-9][0-9]*'
               AND substr(cve, 5) NOT GLOB '*[^0-9-]*'
               AND cve NOT GLOB 'CVE-[0-9][0-9][0-9][0-9]-*-*'),
    status          TEXT    NOT NULL CHECK (status IN ('confirmed', 'suspected', 'mitigated', 'patched', 'false_positive', 'not_relevant')),
    severity        TEXT    NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
    confidence      REAL    NOT NULL CHECK (confidence >= 0 AND confidence <= 1),
    basis           TEXT    NOT NULL CHECK (basis IN ('scan', 'version', 'product')),
    -- {summary, template?, request?, response?, checked_at}
    evidence        TEXT    CHECK (evidence IS NULL OR (json_valid(evidence) AND json_type(evidence) = 'object')),
    first_seen      TEXT    NOT NULL CHECK (first_seen GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    last_seen       TEXT    NOT NULL CHECK (last_seen GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    resolved_by     TEXT    CHECK (resolved_by IS NULL OR length(resolved_by) BETWEEN 1 AND 320),
    resolved_at     TEXT    CHECK (resolved_at IS NULL OR resolved_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    resolution_note TEXT    CHECK (resolution_note IS NULL OR length(resolution_note) <= 500),
    -- INV-2: confirmed only with a scan basis and evidence.
    CHECK (status <> 'confirmed' OR (basis = 'scan' AND evidence IS NOT NULL)),
    UNIQUE (asset_id, cve)
);

CREATE INDEX fnd_finding_status_idx ON fnd_finding (status);
CREATE INDEX fnd_finding_cve_idx ON fnd_finding (cve);
CREATE INDEX fnd_finding_asset_status_idx ON fnd_finding (asset_id, status);

-- Append-only history of a finding (INV-3). A row never changes; it goes away only with its finding.
CREATE TABLE fnd_finding_history (
    id         TEXT NOT NULL PRIMARY KEY CHECK (length(id) BETWEEN 1 AND 96),
    finding_id TEXT NOT NULL REFERENCES fnd_finding (id) ON DELETE CASCADE,
    ts         TEXT NOT NULL CHECK (ts GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    user       TEXT NOT NULL CHECK (length(user) BETWEEN 1 AND 320),
    action     TEXT NOT NULL CHECK (action IN ('created', 'confirmed', 'rescanned', 'rescan_clear', 'reopened', 'patched', 'mitigated', 'false_positive', 'not_relevant')),
    note       TEXT CHECK (note IS NULL OR length(note) <= 600)
);

CREATE INDEX fnd_finding_history_finding_idx ON fnd_finding_history (finding_id, ts);

-- +goose StatementBegin
CREATE TRIGGER fnd_finding_history_no_update BEFORE UPDATE ON fnd_finding_history
BEGIN
    SELECT RAISE(ABORT, 'fnd_finding_history is append-only');
END;
-- +goose StatementEnd
