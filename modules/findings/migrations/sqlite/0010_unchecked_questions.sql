-- +goose Up
-- D-604: a platform-limited CVE that only a person's answer decides is "could not be checked" with a question: reasons
-- platform_unknown (which system or build the device runs) and package_unknown (the distribution's package release). SQLite cannot
-- change a CHECK, so the table is rebuilt with its rows (the next match of each device rewrites them anyway). Forward-only.
CREATE TABLE fnd_unchecked_new (
    asset_id    TEXT NOT NULL CHECK (length(asset_id) BETWEEN 1 AND 96),
    software_id TEXT NOT NULL CHECK (length(software_id) BETWEEN 1 AND 128),
    software    TEXT NOT NULL CHECK (length(software) <= 200),
    version     TEXT NOT NULL CHECK (length(version) <= 200),
    source      TEXT NOT NULL CHECK (length(source) <= 32),
    reason      TEXT NOT NULL CHECK (reason IN ('no_nvd_data', 'no_nvd_versions', 'not_named', 'not_comparable', 'platform_unknown', 'package_unknown')),
    cve         TEXT NOT NULL CHECK (cve GLOB 'CVE-[0-9][0-9][0-9][0-9]-[0-9][0-9][0-9][0-9]*' AND length(cve) <= 32),
    updated_at  TEXT NOT NULL CHECK (updated_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    nvd_pending INTEGER NOT NULL DEFAULT 0 CHECK (nvd_pending IN (0, 1)),
    PRIMARY KEY (asset_id, software_id, cve)
);
INSERT INTO fnd_unchecked_new (asset_id, software_id, software, version, source, reason, cve, updated_at, nvd_pending)
    SELECT asset_id, software_id, software, version, source, reason, cve, updated_at, nvd_pending FROM fnd_unchecked;
DROP TABLE fnd_unchecked;
ALTER TABLE fnd_unchecked_new RENAME TO fnd_unchecked;
