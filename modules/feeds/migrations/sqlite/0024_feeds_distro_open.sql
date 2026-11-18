-- +goose Up
-- A distribution's word "affected, no fix yet" is kept too (status 'open', no fixed version), for the tier CVEs of the source packages
-- the devices run: the Debian Security Tracker's open entries and Ubuntu's OSV entries of a release with no fixed event. Findings'
-- "Updates to plan" says "No fix from <distribution> yet" for them instead of an update to install. SQLite cannot change a CHECK, so the
-- table is rebuilt with its rows and index, as migration 0018 did. Forward-only.
CREATE TABLE feeds_distro_fix_new (
    source_id     TEXT    NOT NULL REFERENCES feeds_source (id) ON DELETE CASCADE,
    distro        TEXT    NOT NULL CHECK (distro IN ('ubuntu', 'debian', 'alpine')),
    release       TEXT    NOT NULL CHECK (length(release) BETWEEN 1 AND 8 AND release NOT GLOB '*[^0-9.]*'),
    package       TEXT    NOT NULL CHECK (length(package) BETWEEN 1 AND 100),
    cve           TEXT    NOT NULL CHECK (cve GLOB 'CVE-[0-9][0-9][0-9][0-9]-[0-9][0-9][0-9][0-9]*' AND length(cve) <= 32),
    status        TEXT    NOT NULL CHECK (status IN ('fixed', 'not_affected', 'open')),
    fixed_version TEXT    CHECK ((status = 'fixed') = (fixed_version IS NOT NULL) AND (fixed_version IS NULL OR length(fixed_version) BETWEEN 1 AND 100)),
    pro           INTEGER NOT NULL DEFAULT 0 CHECK (pro IN (0, 1)),
    PRIMARY KEY (source_id, distro, release, package, cve)
);
INSERT INTO feeds_distro_fix_new (source_id, distro, release, package, cve, status, fixed_version, pro)
    SELECT source_id, distro, release, package, cve, status, fixed_version, pro FROM feeds_distro_fix;
DROP TABLE feeds_distro_fix;
ALTER TABLE feeds_distro_fix_new RENAME TO feeds_distro_fix;
CREATE INDEX feeds_distro_fix_cve_idx ON feeds_distro_fix (cve);
CREATE INDEX feeds_distro_fix_package_idx ON feeds_distro_fix (distro, package);
