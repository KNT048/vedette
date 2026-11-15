-- +goose Up
-- D-615: the day NVD published each CVE of the exploited lists (nvd-kev reads `published` from the same CVE API 2.0 answer as
-- the affected versions), so findings can tell a KEV CVE published more than 12 months ago (a finding only on confirmed
-- evidence) from a recent one. Never CISA's dateAdded. A CVE without a row counts as recent (never closed on missing data).
-- Kept apart from feeds_affected_cve, whose rows CVE.org's ranges replace (D-556). The first nvd-kev pull after this
-- migration is a full one (an empty table asks for it), so every KEV CVE NVD answers for gets its date. Forward-only.
CREATE TABLE feeds_published (
    cve       TEXT NOT NULL PRIMARY KEY CHECK (cve GLOB 'CVE-[0-9][0-9][0-9][0-9]-[0-9][0-9][0-9][0-9]*' AND length(cve) <= 32),
    published TEXT NOT NULL CHECK (published GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]')
) WITHOUT ROWID;
