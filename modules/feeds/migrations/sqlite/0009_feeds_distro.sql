-- +goose Up
-- D-516: what Ubuntu and Debian say about a CVE in their own packages, so findings can tell a backported fix from a vulnerable
-- package (Ubuntu and Debian patch without changing the upstream version). Built-in feeds ubuntu-osv (fixed versions,
-- Canonical's osv-all archive), ubuntu-vex (not affected, Canonical's vex-all archive) and debian-tracker (both, the Debian
-- Security Tracker JSON). Only the CVEs of the CISA list are kept, the only CVEs the findings matcher evaluates. A row is a
-- source package of one release: status fixed with the first fixed version, or not_affected. Each pull replaces its own
-- feed's rows in one transaction; a built-in feed that is removed takes its rows with it. Forward-only.
CREATE TABLE feeds_distro_fix (
    source_id     TEXT    NOT NULL REFERENCES feeds_source (id) ON DELETE CASCADE,
    distro        TEXT    NOT NULL CHECK (distro IN ('ubuntu', 'debian')),
    release       TEXT    NOT NULL CHECK (length(release) BETWEEN 1 AND 8 AND release NOT GLOB '*[^0-9.]*'),
    package       TEXT    NOT NULL CHECK (length(package) BETWEEN 1 AND 100),
    cve           TEXT    NOT NULL CHECK (cve GLOB 'CVE-[0-9][0-9][0-9][0-9]-[0-9][0-9][0-9][0-9]*' AND length(cve) <= 32),
    status        TEXT    NOT NULL CHECK (status IN ('fixed', 'not_affected')),
    fixed_version TEXT    CHECK ((status = 'fixed') = (fixed_version IS NOT NULL) AND (fixed_version IS NULL OR length(fixed_version) BETWEEN 1 AND 100)),
    pro           INTEGER NOT NULL DEFAULT 0 CHECK (pro IN (0, 1)),
    PRIMARY KEY (source_id, distro, release, package, cve)
);
CREATE INDEX feeds_distro_fix_cve_idx ON feeds_distro_fix (cve);
