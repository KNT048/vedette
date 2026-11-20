-- +goose Up
-- The whole schema of the feeds module. It is edited in place until the first public release; docs/SCHEMA.sql
-- shows the schema of every module together. Forward-only: there is no Down section.

CREATE TABLE feeds_source (
    id              TEXT    NOT NULL PRIMARY KEY CHECK (length(id) BETWEEN 1 AND 96),
    builtin         INTEGER NOT NULL CHECK (builtin IN (0, 1)),
    name            TEXT    NOT NULL CHECK (length(name) BETWEEN 1 AND 60),
    kind            TEXT    NOT NULL CHECK (kind IN ('vulnerabilities', 'ioc')),
    format          TEXT    NOT NULL CHECK (format IN ('json', 'csv', 'rss', 'stix', 'lines')),
    url             TEXT    NOT NULL CHECK (length(url) BETWEEN 1 AND 500),
    default_url     TEXT    CHECK ((builtin = 1) = (default_url IS NOT NULL)),
    enabled         INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    interval_hours  INTEGER NOT NULL CHECK (interval_hours BETWEEN 1 AND 168),
    auth_type       TEXT    NOT NULL DEFAULT 'none' CHECK (auth_type IN ('none', 'header', 'bearer', 'basic')),
    auth_header_name TEXT,
    auth_username   TEXT,
    secret_id       TEXT    REFERENCES core_secret (id),
    secret_last4    TEXT    CHECK (secret_last4 IS NULL OR length(secret_last4) = 4),
    parser          TEXT    CHECK (parser IS NULL OR json_valid(parser)),
    license         TEXT,
    created_at      TEXT    NOT NULL CHECK (created_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    last_fetch      TEXT    CHECK (last_fetch IS NULL OR last_fetch GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    last_success    TEXT    CHECK (last_success IS NULL OR last_success GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    failures        INTEGER NOT NULL DEFAULT 0 CHECK (failures >= 0),
    records         INTEGER CHECK (records IS NULL OR records >= 0),
    status          TEXT    NOT NULL DEFAULT 'never' CHECK (status IN ('never', 'ok', 'error')),
    error           TEXT,
    etag            TEXT,
    last_modified   TEXT,
    catalog_version TEXT, rev INTEGER NOT NULL DEFAULT 0 CHECK (rev >= 0), answered_by TEXT, mirror_etag TEXT, mirror_last_modified TEXT, distro_packages TEXT CHECK (distro_packages IS NULL OR (json_valid(distro_packages) AND json_type(distro_packages) = 'array')), full_due INTEGER NOT NULL DEFAULT 0 CHECK (full_due IN (0, 1)), kev_copies TEXT, catalog_released TEXT, stale_watch_from TEXT, stale_alerted_at TEXT, stale_failed_since TEXT, stale_failed_checks INTEGER NOT NULL DEFAULT 0, content_version INTEGER NOT NULL DEFAULT 0 CHECK (content_version >= 0),
    CHECK (builtin = 1 OR parser IS NOT NULL),
    CHECK (secret_id IS NULL OR auth_type <> 'none')
);

CREATE TABLE feeds_vuln (
    cve             TEXT    NOT NULL PRIMARY KEY CHECK (cve GLOB 'CVE-[0-9][0-9][0-9][0-9]-[0-9][0-9][0-9][0-9]*'),
    vendor          TEXT    NOT NULL,
    product         TEXT    NOT NULL,
    product_key     TEXT    NOT NULL, -- lower(vendor)|lower(product): the inventory matching key
    name            TEXT    NOT NULL,
    description     TEXT    NOT NULL DEFAULT '',
    required_action TEXT    NOT NULL DEFAULT '',
    links           TEXT    NOT NULL DEFAULT '[]' CHECK (json_valid(links) AND json_type(links) = 'array'),
    date_added      TEXT    NOT NULL CHECK (date_added GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]'),
    due_date        TEXT    CHECK (due_date IS NULL OR due_date GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]'),
    ransomware      INTEGER NOT NULL DEFAULT 0 CHECK (ransomware IN (0, 1)),
    epss            REAL    CHECK (epss IS NULL OR (epss >= 0 AND epss <= 1)),
    epss_7d_ago     REAL    CHECK (epss_7d_ago IS NULL OR (epss_7d_ago >= 0 AND epss_7d_ago <= 1)),
    has_template    INTEGER NOT NULL DEFAULT 0 CHECK (has_template IN (0, 1)),
    source_id       TEXT    NOT NULL REFERENCES feeds_source (id) ON DELETE CASCADE,
    updated_at      TEXT    NOT NULL CHECK (updated_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z')
, kev_announced_at TEXT CHECK (kev_announced_at IS NULL OR kev_announced_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'));

-- The CVEs that have a nuclei template. Kept on their own so a CVE that reaches KEV after the nuclei pull
-- still gets has_template at once (scan re-checks within 60 minutes only when it has one).
CREATE TABLE feeds_template (
    cve TEXT NOT NULL PRIMARY KEY CHECK (cve GLOB 'CVE-[0-9][0-9][0-9][0-9]-[0-9][0-9][0-9][0-9]*')
);

-- One row per indicator, merged over all feeds that list it. An IP is its exact address, never a /24.
-- The verdict, the score and the category are not stored: they are derived from feeds_ioc_source when read.
CREATE TABLE feeds_ioc (
    id         TEXT NOT NULL PRIMARY KEY CHECK (length(id) BETWEEN 1 AND 96),
    type       TEXT NOT NULL CHECK (type IN ('ip', 'domain', 'url', 'hash')),
    value      TEXT NOT NULL CHECK (length(value) BETWEEN 1 AND 2000),
    first_seen TEXT NOT NULL CHECK (first_seen GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    last_seen  TEXT NOT NULL CHECK (last_seen GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    UNIQUE (type, value)
);

-- Which feed lists which indicator right now. confidence is what the feed said (0..1) or 0.5 when it said nothing.
-- seen is bookkeeping inside one pull transaction (rows not seen again are deleted before commit).
CREATE TABLE feeds_ioc_source (
    ioc_id     TEXT    NOT NULL REFERENCES feeds_ioc (id) ON DELETE CASCADE,
    source_id  TEXT    NOT NULL REFERENCES feeds_source (id) ON DELETE CASCADE,
    last_seen  TEXT    NOT NULL CHECK (last_seen GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    confidence REAL    NOT NULL CHECK (confidence >= 0 AND confidence <= 1),
    seen       INTEGER NOT NULL DEFAULT 1 CHECK (seen IN (0, 1)),
    PRIMARY KEY (ioc_id, source_id)
) WITHOUT ROWID;

-- One row per pull attempt (90 days, but the newest ok row of each feed is always kept).
CREATE TABLE feeds_fetch_log (
    id               TEXT    NOT NULL PRIMARY KEY CHECK (length(id) BETWEEN 1 AND 96),
    source_id        TEXT    NOT NULL REFERENCES feeds_source (id) ON DELETE CASCADE,
    started_at       TEXT    NOT NULL CHECK (started_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    finished_at      TEXT    CHECK (finished_at IS NULL OR finished_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    status           TEXT    NOT NULL CHECK (status IN ('ok', 'error')),
    records_accepted INTEGER NOT NULL DEFAULT 0 CHECK (records_accepted >= 0),
    records_rejected INTEGER NOT NULL DEFAULT 0 CHECK (records_rejected >= 0),
    reject_reasons   TEXT    NOT NULL DEFAULT '[]' CHECK (json_valid(reject_reasons) AND json_type(reject_reasons) = 'array'),
    error            TEXT,
    bytes            INTEGER CHECK (bytes IS NULL OR bytes >= 0),
    etag             TEXT,
    last_modified    TEXT
);

CREATE TABLE feeds_weekly_answer (
    key         TEXT NOT NULL PRIMARY KEY CHECK (length(key) BETWEEN 1 AND 500),
    answer      TEXT NOT NULL CHECK (answer IN ('have', 'not_relevant')),
    user_id     TEXT NOT NULL CHECK (length(user_id) > 0),
    answered_at TEXT NOT NULL CHECK (answered_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z')
, device_added INTEGER NOT NULL DEFAULT 0 CHECK (device_added IN (0, 1)), device_id TEXT CHECK (device_id IS NULL OR length(device_id) BETWEEN 1 AND 64), have_since TEXT CHECK (have_since IS NULL OR have_since GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]'));

CREATE TABLE feeds_affected_cve (
    cve        TEXT NOT NULL PRIMARY KEY CHECK (cve GLOB 'CVE-[0-9][0-9][0-9][0-9]-[0-9][0-9][0-9][0-9]*' AND length(cve) <= 32),
    updated_at TEXT NOT NULL CHECK (updated_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z')
, source TEXT NOT NULL DEFAULT 'nvd' CHECK (source IN ('nvd', 'cve.org', 'cve.org-partial')));

CREATE TABLE feeds_affected (
    cve        TEXT NOT NULL REFERENCES feeds_affected_cve (cve) ON DELETE CASCADE,
    cpe        TEXT NOT NULL CHECK (cpe GLOB 'cpe:2.3:*' AND length(cpe) <= 500),
    start_incl TEXT NOT NULL CHECK (length(start_incl) <= 100),
    start_excl TEXT NOT NULL CHECK (length(start_excl) <= 100),
    end_incl   TEXT NOT NULL CHECK (length(end_incl) <= 100),
    end_excl   TEXT NOT NULL CHECK (length(end_excl) <= 100)
);

CREATE TABLE feeds_cveorg_checked (
    cve        TEXT NOT NULL PRIMARY KEY CHECK (cve GLOB 'CVE-[0-9][0-9][0-9][0-9]-[0-9][0-9][0-9][0-9]*' AND length(cve) <= 32),
    checked_at TEXT NOT NULL CHECK (checked_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z')
);

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

CREATE TABLE feeds_epss_baseline (
    id    INTEGER NOT NULL PRIMARY KEY CHECK (id = 1),
    url   TEXT    NOT NULL CHECK (length(url) <= 2048),
    count INTEGER NOT NULL CHECK (count >= 0)
, score_date TEXT CHECK (score_date IS NULL OR score_date GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]'));

CREATE TABLE feeds_recent_cve (
    cve           TEXT NOT NULL PRIMARY KEY CHECK (cve GLOB 'CVE-[0-9][0-9][0-9][0-9]-[0-9][0-9][0-9][0-9]*' AND length(cve) <= 32),
    published     TEXT NOT NULL CHECK (published GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    last_modified TEXT NOT NULL CHECK (last_modified GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    status        TEXT NOT NULL CHECK (length(status) BETWEEN 1 AND 40),
    severity      TEXT CHECK (severity IS NULL OR severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'NONE')),
    score         REAL CHECK (score IS NULL OR score BETWEEN 0 AND 10)
, cvss_score REAL CHECK (cvss_score IS NULL OR cvss_score BETWEEN 0 AND 10), cvss_version TEXT CHECK (cvss_version IS NULL OR cvss_version IN ('4.0', '3.1', '3.0', '2.0')), cvss_source TEXT CHECK (cvss_source IS NULL OR cvss_source IN ('nvd', 'cna')), cvss_vector TEXT CHECK (cvss_vector IS NULL OR (length(cvss_vector) <= 200 AND (cvss_vector GLOB 'CVSS:[34].[01]/*' OR cvss_vector GLOB 'AV:[LAN]/*'))));

CREATE TABLE feeds_recent_affected (
    cve        TEXT NOT NULL REFERENCES feeds_recent_cve (cve) ON DELETE CASCADE,
    cpe        TEXT NOT NULL CHECK (cpe GLOB 'cpe:2.3:*' AND length(cpe) <= 500),
    start_incl TEXT NOT NULL CHECK (length(start_incl) <= 100),
    start_excl TEXT NOT NULL CHECK (length(start_excl) <= 100),
    end_incl   TEXT NOT NULL CHECK (length(end_incl) <= 100),
    end_excl   TEXT NOT NULL CHECK (length(end_excl) <= 100)
, platforms TEXT CHECK (platforms IS NULL OR (json_valid(platforms) AND json_type(platforms) = 'array')));

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

CREATE TABLE feeds_published (
    cve       TEXT NOT NULL PRIMARY KEY CHECK (cve GLOB 'CVE-[0-9][0-9][0-9][0-9]-[0-9][0-9][0-9][0-9]*' AND length(cve) <= 32),
    published TEXT NOT NULL CHECK (published GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]')
, source TEXT NOT NULL DEFAULT 'nvd' CHECK (source IN ('nvd', 'cve.org'))) WITHOUT ROWID;

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

-- D-603: the Windows releases Microsoft's release information pages list (feed windows-releases), handed to core/winrel, which answers
-- from its own table first. Replaced whole by each good pull; a failed pull or a feed turned off keeps the last good list. Server or
-- client by build, the NVD name Vedette gives it, the first build of its line (the release whose monthly update it shares), the day
-- of general availability and the revision of its first public build (0: not known). Forward-only.
CREATE TABLE feeds_winrel (
    build   INTEGER NOT NULL CHECK (build BETWEEN 10240 AND 99999),
    server  INTEGER NOT NULL CHECK (server IN (0, 1)),
    product TEXT    NOT NULL UNIQUE CHECK (length(product) BETWEEN 1 AND 60 AND product GLOB 'windows_*'),
    display TEXT    NOT NULL CHECK (length(display) BETWEEN 1 AND 60),
    line    INTEGER NOT NULL CHECK (line BETWEEN 10240 AND 99999),
    ga      TEXT    NOT NULL CHECK (ga GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]'),
    ga_rev  INTEGER NOT NULL CHECK (ga_rev BETWEEN 0 AND 999999),
    PRIMARY KEY (build, server)
) WITHOUT ROWID;

CREATE TABLE feeds_winrel_update (
    build  INTEGER NOT NULL CHECK (build BETWEEN 10240 AND 99999),
    server INTEGER NOT NULL CHECK (server IN (0, 1)),
    rev    INTEGER NOT NULL CHECK (rev BETWEEN 1 AND 999999),
    kb     TEXT    NOT NULL CHECK (kb = '' OR (kb GLOB 'KB[0-9]*' AND kb NOT GLOB 'KB*[^0-9]*' AND length(kb) BETWEEN 8 AND 10)),
    day    TEXT    NOT NULL CHECK (day GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]'), hotpatch INTEGER NOT NULL DEFAULT 0 CHECK (hotpatch IN (0, 1)),
    PRIMARY KEY (build, server, rev)
) WITHOUT ROWID;

CREATE TABLE "feeds_distro_fix" (
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

CREATE UNIQUE INDEX feeds_source_name_uq ON feeds_source (lower(name));

CREATE INDEX feeds_source_kind_idx ON feeds_source (kind, enabled);

CREATE INDEX feeds_vuln_key_idx ON feeds_vuln (product_key);

CREATE INDEX feeds_vuln_date_idx ON feeds_vuln (date_added DESC, cve DESC);

CREATE INDEX feeds_vuln_source_idx ON feeds_vuln (source_id);

CREATE INDEX feeds_ioc_last_seen_idx ON feeds_ioc (last_seen);

CREATE INDEX feeds_ioc_source_src_idx ON feeds_ioc_source (source_id);

CREATE INDEX feeds_fetch_log_source_idx ON feeds_fetch_log (source_id, started_at DESC);

CREATE INDEX feeds_vuln_kev_announced ON feeds_vuln (kev_announced_at, cve) WHERE kev_announced_at IS NOT NULL;

CREATE INDEX feeds_affected_cve_idx ON feeds_affected (cve);

CREATE INDEX feeds_recent_cve_published_idx ON feeds_recent_cve (published);

CREATE INDEX feeds_recent_affected_cve_idx ON feeds_recent_affected (cve);

CREATE INDEX feeds_recent_affected_cpe_idx ON feeds_recent_affected (cpe);

CREATE INDEX feeds_distro_fix_cve_idx ON feeds_distro_fix (cve);

CREATE INDEX feeds_distro_fix_package_idx ON feeds_distro_fix (distro, package);
