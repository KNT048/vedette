-- +goose Up
-- D-613, D-614: the data of CVE tiers 2 (likely to be exploited, EPSS) and 3 (published in the last 12 months).
-- feeds_epss: FIRST's EPSS score of every CVE (built-in feed epss-all, the daily file of all scores); gen is the pull that
-- wrote the row, so a pull that read the whole file drops the CVEs it no longer lists.
-- feeds_recent_cve: the NVD record of each CVE published in the last 12 months (built-in feed nvd-recent): dates, NVD's
-- status and the CVSS severity; its vulnerable CPE match entries are in feeds_recent_affected (the shape of feeds_affected,
-- kept apart so nvd-kev's full pull never deletes them and the KEV matcher never reads them).
-- feeds_recent_cursor (one row at most): how far an unfinished paged pull of nvd-recent got (mode fill or update), so the next
-- pull goes on; after a finished pull, mode done and until = the time the data is complete up to, where the next update starts.
-- Forward-only.
CREATE TABLE feeds_epss (
    cve        TEXT    NOT NULL PRIMARY KEY CHECK (cve GLOB 'CVE-[0-9][0-9][0-9][0-9]-[0-9][0-9][0-9][0-9]*' AND length(cve) <= 32),
    epss       REAL    NOT NULL CHECK (epss BETWEEN 0 AND 1),
    percentile REAL    NOT NULL CHECK (percentile BETWEEN 0 AND 1),
    gen        INTEGER NOT NULL
) WITHOUT ROWID;
CREATE TABLE feeds_recent_cve (
    cve           TEXT NOT NULL PRIMARY KEY CHECK (cve GLOB 'CVE-[0-9][0-9][0-9][0-9]-[0-9][0-9][0-9][0-9]*' AND length(cve) <= 32),
    published     TEXT NOT NULL CHECK (published GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    last_modified TEXT NOT NULL CHECK (last_modified GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    status        TEXT NOT NULL CHECK (length(status) BETWEEN 1 AND 40),
    severity      TEXT CHECK (severity IS NULL OR severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'NONE')),
    score         REAL CHECK (score IS NULL OR score BETWEEN 0 AND 10)
);
CREATE INDEX feeds_recent_cve_published_idx ON feeds_recent_cve (published);
CREATE TABLE feeds_recent_affected (
    cve        TEXT NOT NULL REFERENCES feeds_recent_cve (cve) ON DELETE CASCADE,
    cpe        TEXT NOT NULL CHECK (cpe GLOB 'cpe:2.3:*' AND length(cpe) <= 500),
    start_incl TEXT NOT NULL CHECK (length(start_incl) <= 100),
    start_excl TEXT NOT NULL CHECK (length(start_excl) <= 100),
    end_incl   TEXT NOT NULL CHECK (length(end_incl) <= 100),
    end_excl   TEXT NOT NULL CHECK (length(end_excl) <= 100)
);
CREATE INDEX feeds_recent_affected_cve_idx ON feeds_recent_affected (cve);
CREATE INDEX feeds_recent_affected_cpe_idx ON feeds_recent_affected (cpe); -- slice 2 matches devices by CPE
CREATE TABLE feeds_recent_cursor (
    id         INTEGER NOT NULL PRIMARY KEY CHECK (id = 1),
    url        TEXT    NOT NULL CHECK (length(url) <= 2048),
    mode       TEXT    NOT NULL CHECK (mode IN ('fill', 'update', 'done')),
    win_from   TEXT    NOT NULL,
    win_to     TEXT    NOT NULL,
    until      TEXT    NOT NULL,
    next_index INTEGER NOT NULL CHECK (next_index >= 0),
    total      INTEGER NOT NULL CHECK (total >= 0)
);
