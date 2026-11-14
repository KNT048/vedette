-- +goose Up
-- D-556: the affected versions of an exploited CVE NVD has not analysed come from the CNA's own record on CVE.org (built-in
-- feed cve-org). feeds_affected_cve.source says whose ranges a CVE has: 'nvd' (every row before this change) or 'cve.org';
-- NVD's ranges replace CVE.org's as soon as NVD has some. feeds_cveorg_checked remembers when each CVE's record was last
-- read, so a pull asks only for the CVEs not read lately. Forward-only.
ALTER TABLE feeds_affected_cve ADD COLUMN source TEXT NOT NULL DEFAULT 'nvd' CHECK (source IN ('nvd', 'cve.org'));
CREATE TABLE IF NOT EXISTS feeds_cveorg_checked (
    cve        TEXT NOT NULL PRIMARY KEY CHECK (cve GLOB 'CVE-[0-9][0-9][0-9][0-9]-[0-9][0-9][0-9][0-9]*' AND length(cve) <= 32),
    checked_at TEXT NOT NULL CHECK (checked_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z')
);
