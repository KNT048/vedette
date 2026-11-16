-- +goose Up
-- #825 (INV-28): the CVSS base score every finding shows next to its exploited status. feeds_cvss: the score of each CVE of the
-- exploited lists, from nvd-kev's own CVE API 2.0 answer (the `metrics` of the same records it reads the affected versions from; no
-- new request): the newest CVSS version present (4.0, 3.1, 3.0), NVD's own score ("Primary", source nvd) before the CNA's
-- ("Secondary", source cna), with that entry's vector string ('' when NVD gave none usable; FIRST asks that a score be shown with
-- its vector). A CVE without a row has no score ("No score", never 0). The table is empty after this migration, so
-- the next nvd-kev pull is a full one (about 20 requests), as for feeds_published (D-615).
-- feeds_recent_cve keeps the version, source and vector of the score nvd-recent already stores, for findings of CVEs not on the exploited
-- lists; NULL for a row stored before this migration (no refill: the next change of the record, or the next fill, gives them).
-- Forward-only.
CREATE TABLE feeds_cvss (
    cve     TEXT NOT NULL PRIMARY KEY CHECK (cve GLOB 'CVE-[0-9][0-9][0-9][0-9]-[0-9][0-9][0-9][0-9]*' AND length(cve) <= 32),
    score   REAL NOT NULL CHECK (score BETWEEN 0 AND 10),
    version TEXT NOT NULL CHECK (version IN ('4.0', '3.1', '3.0')),
    source  TEXT NOT NULL CHECK (source IN ('nvd', 'cna')),
    vector  TEXT NOT NULL CHECK (length(vector) <= 200 AND (vector = '' OR vector GLOB 'CVSS:[34].[01]/*'))
) WITHOUT ROWID;
ALTER TABLE feeds_recent_cve ADD COLUMN cvss_version TEXT CHECK (cvss_version IS NULL OR cvss_version IN ('4.0', '3.1', '3.0'));
ALTER TABLE feeds_recent_cve ADD COLUMN cvss_source TEXT CHECK (cvss_source IS NULL OR cvss_source IN ('nvd', 'cna'));
ALTER TABLE feeds_recent_cve ADD COLUMN cvss_vector TEXT CHECK (cvss_vector IS NULL OR (length(cvss_vector) <= 200 AND cvss_vector GLOB 'CVSS:[34].[01]/*'));
