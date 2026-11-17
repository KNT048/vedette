-- +goose Up
-- D-602 (review r1 H2 of #939): the (device, CVE) pairs the "could not be checked" list has ever held for a device, or that had a
-- finding: a pair new here is announced once (findings.unchecked.added, one event per device and match write, notify sends one
-- notice listing the CVEs), never again. Seeded with every pair the box already listed or had a finding for, so the upgrade itself
-- (old product findings closing into the list) announces nothing. Removed with the device; moved on a merge. No foreign keys
-- (inventory owns the ids, rules/modules.md). Forward-only (DATA_MODEL 6, rule 1).
CREATE TABLE fnd_unchecked_seen (
    asset_id   TEXT NOT NULL CHECK (length(asset_id) BETWEEN 1 AND 96),
    cve        TEXT NOT NULL CHECK (cve GLOB 'CVE-[0-9][0-9][0-9][0-9]-[0-9][0-9][0-9][0-9]*' AND length(cve) <= 32),
    first_seen TEXT NOT NULL CHECK (first_seen GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    PRIMARY KEY (asset_id, cve)
) WITHOUT ROWID;
INSERT OR IGNORE INTO fnd_unchecked_seen (asset_id, cve, first_seen) SELECT asset_id, cve, updated_at FROM fnd_unchecked;
INSERT OR IGNORE INTO fnd_unchecked_seen (asset_id, cve, first_seen) SELECT asset_id, cve, first_seen FROM fnd_finding;
-- review r2 M1: no_nvd_data while NVD has not answered for the CVE yet ("waiting for NVD's data"), not "NVD has no data"
ALTER TABLE fnd_unchecked ADD COLUMN nvd_pending INTEGER NOT NULL DEFAULT 0 CHECK (nvd_pending IN (0, 1));
