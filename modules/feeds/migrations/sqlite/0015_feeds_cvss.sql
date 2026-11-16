-- +goose Up
-- #825 (INV-28): the CVSS base score every finding shows next to its exploited status, from the NVD records the box already pulls
-- (the `metrics` of the same CVE API 2.0 answers; no new request). Rule (feeds cvssOf): the newest CVSS version present (4.0, 3.1,
-- 3.0, then 2.0 when NVD has nothing newer), NVD's own score ("Primary", source nvd) before another scorer's ("Secondary", source cna:
-- the CNA or CISA's ADP); an entry counts only with a valid vector of its version (FIRST: a score is shown with its vector), else the
-- next one is tried. A CVE without a score has no row ("No CVSS score", never 0).
-- feeds_cvss: the score of each CVE of the exploited lists, written by nvd-kev. feeds_source.full_due = 1 asks for one full pull of
-- nvd-kev at the next 5-minute check (so every KEV CVE gets its score; about 20 requests), cleared by the first full pull that is
-- stored: a one-time mark, not "the table is empty" (review r1 L1, r2 M1).
-- feeds_recent_cve.cvss_*: the same pick for nvd-recent (a CVE not on the exploited lists), kept apart from severity/score, which tier 3
-- reads by its own rule (INV-24). No refill (review r2 M2): a row stored before gets them when NVD changes the record, or at the next
-- full fill; until then it has no CVSS score. Forward-only.
CREATE TABLE feeds_cvss (
    cve     TEXT NOT NULL PRIMARY KEY CHECK (cve GLOB 'CVE-[0-9][0-9][0-9][0-9]-[0-9][0-9][0-9][0-9]*' AND length(cve) <= 32),
    score   REAL NOT NULL CHECK (score BETWEEN 0 AND 10),
    version TEXT NOT NULL CHECK (version IN ('4.0', '3.1', '3.0', '2.0')),
    source  TEXT NOT NULL CHECK (source IN ('nvd', 'cna')),
    vector  TEXT NOT NULL CHECK (length(vector) <= 200 AND (vector GLOB 'CVSS:[34].[01]/*' OR vector GLOB 'AV:[LAN]/*'))
) WITHOUT ROWID;
ALTER TABLE feeds_source ADD COLUMN full_due INTEGER NOT NULL DEFAULT 0 CHECK (full_due IN (0, 1));
UPDATE feeds_source SET full_due = 1 WHERE id = 'nvd-kev';
ALTER TABLE feeds_recent_cve ADD COLUMN cvss_score REAL CHECK (cvss_score IS NULL OR cvss_score BETWEEN 0 AND 10);
ALTER TABLE feeds_recent_cve ADD COLUMN cvss_version TEXT CHECK (cvss_version IS NULL OR cvss_version IN ('4.0', '3.1', '3.0', '2.0'));
ALTER TABLE feeds_recent_cve ADD COLUMN cvss_source TEXT CHECK (cvss_source IS NULL OR cvss_source IN ('nvd', 'cna'));
ALTER TABLE feeds_recent_cve ADD COLUMN cvss_vector TEXT CHECK (cvss_vector IS NULL OR (length(cvss_vector) <= 200 AND (cvss_vector GLOB 'CVSS:[34].[01]/*' OR cvss_vector GLOB 'AV:[LAN]/*')));
