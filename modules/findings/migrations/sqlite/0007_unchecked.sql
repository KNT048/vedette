-- +goose Up
-- #910 phase 1: the exploited CVEs of software a device has that Vedette could not check (no NVD data, no NVD versions, NVD
-- names other products, a version that does not compare): one row per (device, software, CVE) with its reason. Rewritten for
-- the device on every match of it in the same transaction as its findings (like fnd_version_needed), removed with the device.
-- GET /findings `unchecked` and Home's count leave out the CVEs the device has a finding for. Not a finding: no status, no
-- history. software_id is the inventory row, or "os:<asset>" for the network OS a device states without one. No foreign keys
-- (inventory owns the ids, rules/modules.md). Forward-only (DATA_MODEL 6, rule 1).
CREATE TABLE fnd_unchecked (
    asset_id    TEXT NOT NULL CHECK (length(asset_id) BETWEEN 1 AND 96),
    software_id TEXT NOT NULL CHECK (length(software_id) BETWEEN 1 AND 128),
    software    TEXT NOT NULL CHECK (length(software) <= 200),
    version     TEXT NOT NULL CHECK (length(version) <= 200),
    source      TEXT NOT NULL CHECK (length(source) <= 32),
    reason      TEXT NOT NULL CHECK (reason IN ('no_nvd_data', 'no_nvd_versions', 'not_named', 'not_comparable')),
    cve         TEXT NOT NULL CHECK (cve GLOB 'CVE-[0-9][0-9][0-9][0-9]-[0-9][0-9][0-9][0-9]*' AND length(cve) <= 32),
    updated_at  TEXT NOT NULL CHECK (updated_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    PRIMARY KEY (asset_id, software_id, cve)
);
