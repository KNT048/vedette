-- +goose Up
-- D-500: the NVD affected versions of the exploited list (built-in feed nvd-kev). feeds_affected_cve says which CVEs NVD
-- answered for (a CVE with no vulnerable entry is still "known"); feeds_affected holds each vulnerable CPE match entry
-- with its range ('' = no bound). A pull replaces the rows of every CVE it got, in one transaction. Forward-only.
CREATE TABLE feeds_affected_cve (
    cve        TEXT NOT NULL PRIMARY KEY CHECK (cve GLOB 'CVE-[0-9][0-9][0-9][0-9]-[0-9][0-9][0-9][0-9]*' AND length(cve) <= 32),
    updated_at TEXT NOT NULL CHECK (updated_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z')
);
CREATE TABLE feeds_affected (
    cve        TEXT NOT NULL REFERENCES feeds_affected_cve (cve) ON DELETE CASCADE,
    cpe        TEXT NOT NULL CHECK (cpe GLOB 'cpe:2.3:*' AND length(cpe) <= 500),
    start_incl TEXT NOT NULL CHECK (length(start_incl) <= 100),
    start_excl TEXT NOT NULL CHECK (length(start_excl) <= 100),
    end_incl   TEXT NOT NULL CHECK (length(end_incl) <= 100),
    end_excl   TEXT NOT NULL CHECK (length(end_excl) <= 100)
);
CREATE INDEX feeds_affected_cve_idx ON feeds_affected (cve);
