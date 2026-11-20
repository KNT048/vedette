-- +goose Up
-- D-500: a software whose product is on the exploited list but whose version is missing or unreadable gets ONE row here
-- ("add the version to check N exploited CVEs") instead of one finding per CVE. Rewritten for the device on every match
-- of it (UpsertFromMatch), removed with the device (OnAssetDeleted, reconcile). Not a finding: no status, no history.
-- asset_id and software_id have no foreign key (inventory owns them, rules/modules.md). Forward-only (DATA_MODEL 6, rule 1).
CREATE TABLE fnd_version_needed (
    asset_id    TEXT    NOT NULL CHECK (length(asset_id) BETWEEN 1 AND 96),
    software_id TEXT    NOT NULL CHECK (length(software_id) BETWEEN 1 AND 96),
    software    TEXT    NOT NULL CHECK (length(software) <= 200),
    version     TEXT    NOT NULL CHECK (length(version) <= 200),
    cves        INTEGER NOT NULL CHECK (cves > 0),
    updated_at  TEXT    NOT NULL CHECK (updated_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    PRIMARY KEY (asset_id, software_id)
);
