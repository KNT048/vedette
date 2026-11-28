-- +goose Up
-- feeds_distro_triage: a distribution's stated word that it is still triaging a CVE for a source package of a release (Ubuntu VEX
-- under_investigation, of a release or of its Ubuntu Pro pocket; Debian undetermined), replaced with the feed's feeds_distro_fix rows
-- by each good pull (applyDistro). Findings reads it as the status under_investigation: it decides nothing, outranks an OSV record
-- without a fixed event, and names why the pair stays undecided. A table of its own, not a new status of feeds_distro_fix (whose CHECK
-- would need a rebuild): a release rolled back never reads these rows, so it never takes a triage for "affected". Add-only.
CREATE TABLE feeds_distro_triage (
    source_id TEXT NOT NULL REFERENCES feeds_source (id) ON DELETE CASCADE,
    distro    TEXT NOT NULL CHECK (distro IN ('ubuntu', 'debian', 'alpine')),
    release   TEXT NOT NULL CHECK (length(release) BETWEEN 1 AND 8 AND release NOT GLOB '*[^0-9.]*'),
    package   TEXT NOT NULL CHECK (length(package) BETWEEN 1 AND 100),
    cve       TEXT NOT NULL CHECK (cve GLOB 'CVE-[0-9][0-9][0-9][0-9]-[0-9][0-9][0-9][0-9]*' AND length(cve) <= 32),
    PRIMARY KEY (source_id, distro, release, package, cve)
);

CREATE INDEX feeds_distro_triage_cve_idx ON feeds_distro_triage (cve);
