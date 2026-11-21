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
    catalog_version TEXT, rev INTEGER NOT NULL DEFAULT 0 CHECK (rev >= 0), answered_by TEXT, mirror_etag TEXT, mirror_last_modified TEXT, distro_packages TEXT CHECK (distro_packages IS NULL OR (json_valid(distro_packages) AND json_type(distro_packages) = 'array')), kev_copies TEXT, catalog_released TEXT, stale_watch_from TEXT, stale_alerted_at TEXT, stale_failed_since TEXT, stale_failed_checks INTEGER NOT NULL DEFAULT 0,
    CHECK (builtin = 1 OR parser IS NOT NULL),
    CHECK (secret_id IS NULL OR auth_type <> 'none')
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

-- feeds_epss: FIRST's EPSS score of every CVE (built-in feed epss-all, the daily file of all scores); gen is the pull that wrote the
-- row, so a pull that read the whole file drops the CVEs it no longer lists. The one store of EPSS scores.
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

-- The daily EPSS score of the CVEs that have an exploited-list entry or a signal, for the last days only (epssHistKeep): the
-- "rising" display compares today's score with the one of a week ago.
CREATE TABLE feeds_epss_hist (
    cve  TEXT NOT NULL CHECK (cve GLOB 'CVE-[0-9][0-9][0-9][0-9]-[0-9][0-9][0-9][0-9]*' AND length(cve) <= 32),
    day  TEXT NOT NULL CHECK (day GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]'),
    epss REAL NOT NULL CHECK (epss BETWEEN 0 AND 1),
    PRIMARY KEY (cve, day)
) WITHOUT ROWID;

-- The vulnerability catalogue: one row per CVE the box keeps, whichever source brought it. Which CVEs it holds is a rule, not a
-- table (retainedCVE): published inside the window, or on an exploited list (feeds_kev), or with a qualifying signal
-- (feeds_signal) of any age, or pinned by an open finding. nvd_status and nvd_at are NULL until NVD answered for the CVE;
-- record_at is when the CVE Program record was last read. A row an exploited list creates before NVD answers has only its id.
CREATE TABLE feeds_cve (
    cve               TEXT NOT NULL PRIMARY KEY CHECK (cve GLOB 'CVE-[0-9][0-9][0-9][0-9]-[0-9][0-9][0-9][0-9]*' AND length(cve) <= 32),
    published         TEXT CHECK (published IS NULL OR published GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    modified          TEXT CHECK (modified IS NULL OR modified GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    nvd_status        TEXT CHECK (nvd_status IS NULL OR length(nvd_status) BETWEEN 1 AND 40),
    nvd_at            TEXT CHECK (nvd_at IS NULL OR nvd_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    record_at         TEXT CHECK (record_at IS NULL OR record_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    title             TEXT NOT NULL DEFAULT '' CHECK (length(title) <= 500),
    description       TEXT NOT NULL DEFAULT '' CHECK (length(description) <= 4000),
    cwe               TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(cwe) AND json_type(cwe) = 'array'),
    solution          TEXT NOT NULL DEFAULT '' CHECK (length(solution) <= 4000),
    workaround        TEXT NOT NULL DEFAULT '' CHECK (length(workaround) <= 4000),
    ssvc_exploitation TEXT CHECK (ssvc_exploitation IS NULL OR (length(ssvc_exploitation) BETWEEN 1 AND 40 AND ssvc_exploitation NOT GLOB '*[^a-z0-9_]*')),
    ssvc_automatable  TEXT CHECK (ssvc_automatable IS NULL OR (length(ssvc_automatable) BETWEEN 1 AND 40 AND ssvc_automatable NOT GLOB '*[^a-z0-9_]*')),
    ssvc_impact       TEXT CHECK (ssvc_impact IS NULL OR (length(ssvc_impact) BETWEEN 1 AND 40 AND ssvc_impact NOT GLOB '*[^a-z0-9_]*')),
    updated_at        TEXT NOT NULL CHECK (updated_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z')
);

-- The CVSS base scores of a CVE, one per scorer and version: source nvd (NVD's own), cna (the CVE Numbering Authority) or adp
-- (CISA's ADP). PickCVSS chooses the one every page shows. A score is kept only with a valid vector of its version.
CREATE TABLE feeds_cve_metric (
    cve     TEXT NOT NULL REFERENCES feeds_cve (cve) ON DELETE CASCADE,
    source  TEXT NOT NULL CHECK (length(source) BETWEEN 1 AND 40 AND source NOT GLOB '*[^a-z0-9_]*'),
    version TEXT NOT NULL CHECK (version IN ('4.0', '3.1', '3.0', '2.0')),
    score   REAL NOT NULL CHECK (score BETWEEN 0 AND 10),
    vector  TEXT NOT NULL CHECK (length(vector) <= 200 AND (vector GLOB 'CVSS:[34].[01]/*' OR vector GLOB 'AV:[LAN]/*')),
    PRIMARY KEY (cve, source, version)
) WITHOUT ROWID;

-- The affected versions of a CVE as each origin states them: nvd (NVD's vulnerable CPE match entries, with the "running on"
-- operating systems of an AND configuration in platforms), cna (the CNA's affected[] list of the CVE record) or adp (an ADP's list:
-- CISA's, a supplier's). NVD's rows win when NVD has any (rangeOrigin). default_status is the CVE record entry's defaultStatus
-- (affected, unaffected, or unknown when it gives none): a record's list is complete when every row says affected or unaffected; ''
-- for NVD's rows. part, vendor and product are the CPE's, lower case; a record entry without a CPE has part '' and the key of its own
-- names (RecordProductKey: "paloalto", "panos"). cpe is the full match criteria when the origin gave one. An exact version is a range
-- from and to it (start_incl = end_incl). fixed is the release the record says fixes a range; version_type the record's versionType.
CREATE TABLE feeds_cve_range (
    id           INTEGER NOT NULL PRIMARY KEY,
    cve          TEXT    NOT NULL REFERENCES feeds_cve (cve) ON DELETE CASCADE,
    origin       TEXT    NOT NULL CHECK (length(origin) BETWEEN 1 AND 40 AND origin NOT GLOB '*[^a-z0-9_]*'),
    part         TEXT    NOT NULL CHECK (length(part) <= 1),
    vendor       TEXT    NOT NULL CHECK (length(vendor) <= 200),
    product      TEXT    NOT NULL CHECK (length(product) <= 200),
    cpe          TEXT    NOT NULL CHECK (cpe = '' OR (cpe GLOB 'cpe:2.3:*' AND length(cpe) <= 500)),
    start_incl   TEXT    NOT NULL CHECK (length(start_incl) <= 100),
    start_excl   TEXT    NOT NULL CHECK (length(start_excl) <= 100),
    end_incl     TEXT    NOT NULL CHECK (length(end_incl) <= 100),
    end_excl     TEXT    NOT NULL CHECK (length(end_excl) <= 100),
    fixed        TEXT    NOT NULL DEFAULT '' CHECK (length(fixed) <= 100),
    version_type TEXT    NOT NULL DEFAULT '' CHECK (length(version_type) <= 40),
    default_status TEXT  NOT NULL DEFAULT '' CHECK (default_status IN ('', 'affected', 'unaffected', 'unknown')),
    platforms    TEXT    CHECK (platforms IS NULL OR (json_valid(platforms) AND json_type(platforms) = 'array'))
);

-- The references of a CVE's record (the CNA's, then the ADPs'), with the tags their publisher gave them (vendor-advisory, patch,
-- mitigation, exploit …; read whole). Kept only for the CVEs that matter to the box: an exploited-list entry, a qualifying signal or an
-- open finding; source is cna or adp. Written only by the CVE records pull, replaced whole with each record read.
CREATE TABLE feeds_cve_ref (
    cve    TEXT NOT NULL REFERENCES feeds_cve (cve) ON DELETE CASCADE,
    url    TEXT NOT NULL CHECK (length(url) BETWEEN 9 AND 500 AND (url GLOB 'https://*' OR url GLOB 'http://*')),
    tags   TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(tags) AND json_type(tags) = 'array'),
    source TEXT NOT NULL CHECK (length(source) BETWEEN 1 AND 40 AND source NOT GLOB '*[^a-z0-9_]*'),
    PRIMARY KEY (cve, url)
) WITHOUT ROWID;

-- An entry of an exploited list, in the list's own words: list cisa (the CISA KEV catalog), vulncheck (VulnCheck KEV) or
-- custom:<feed id> (a custom vulnerability feed). The same CVE may be on several lists; the CISA list's entry is the one the pages
-- name (ownerOrder). announced_at is when the box announced a CISA entry as new (feeds.vuln.new_kev).
CREATE TABLE feeds_kev (
    cve             TEXT    NOT NULL REFERENCES feeds_cve (cve) ON DELETE CASCADE,
    list            TEXT    NOT NULL CHECK (length(list) BETWEEN 1 AND 110),
    source_id       TEXT    NOT NULL REFERENCES feeds_source (id) ON DELETE CASCADE,
    vendor          TEXT    NOT NULL,
    product         TEXT    NOT NULL,
    name            TEXT    NOT NULL,
    description     TEXT    NOT NULL DEFAULT '',
    required_action TEXT    NOT NULL DEFAULT '',
    links           TEXT    NOT NULL DEFAULT '[]' CHECK (json_valid(links) AND json_type(links) = 'array'),
    date_added      TEXT    NOT NULL CHECK (date_added GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]'),
    due_date        TEXT    CHECK (due_date IS NULL OR due_date GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]'),
    ransomware      INTEGER NOT NULL DEFAULT 0 CHECK (ransomware IN (0, 1)),
    announced_at    TEXT    CHECK (announced_at IS NULL OR announced_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    updated_at      TEXT    NOT NULL CHECK (updated_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    PRIMARY KEY (cve, list)
);

-- Why a CVE is urgent, and since when: one row per CVE, kind (exploited, public_exploit, ids_rule …) and source (the feed id).
-- first_seen is the date the source gives, else when this box first saw it; qualifies is whether the row passes its kind's quality
-- rule (a row that does not yet keeps its first_seen for later). An exploited-list entry is also a signal row, written with it.
CREATE TABLE feeds_signal (
    cve        TEXT    NOT NULL CHECK (cve GLOB 'CVE-[0-9][0-9][0-9][0-9]-[0-9][0-9][0-9][0-9]*' AND length(cve) <= 32),
    kind       TEXT    NOT NULL CHECK (length(kind) BETWEEN 1 AND 40 AND kind NOT GLOB '*[^a-z0-9_]*'),
    source     TEXT    NOT NULL CHECK (length(source) BETWEEN 1 AND 96),
    first_seen TEXT    NOT NULL CHECK (first_seen GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    stored_at  TEXT    NOT NULL CHECK (stored_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    last_seen  TEXT    NOT NULL CHECK (last_seen GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    qualifies  INTEGER NOT NULL CHECK (qualifies IN (0, 1)),
    url        TEXT    NOT NULL DEFAULT '' CHECK (length(url) <= 500),
    detail     TEXT    CHECK (detail IS NULL OR (json_valid(detail) AND json_type(detail) = 'object' AND length(detail) <= 500)),
    PRIMARY KEY (cve, kind, source)
) WITHOUT ROWID;

-- Where each paged NVD pull stands, one row per selector: recent (the CVEs published inside the window, then the records NVD changed)
-- and walk (one pass over the whole NVD set for the kept CVEs older than the window). mode fill/walk/update is an unfinished pull;
-- after a finished one, mode done and until = the time the data is complete up to, where the next update starts.
CREATE TABLE feeds_nvd_cursor (
    selector   TEXT    NOT NULL PRIMARY KEY CHECK (length(selector) BETWEEN 1 AND 40 AND selector NOT GLOB '*[^a-z0-9_]*'),
    url        TEXT    NOT NULL CHECK (length(url) <= 2048),
    mode       TEXT    NOT NULL CHECK (mode IN ('fill', 'walk', 'update', 'done')),
    win_from   TEXT    NOT NULL,
    win_to     TEXT    NOT NULL,
    until      TEXT    NOT NULL,
    next_index INTEGER NOT NULL CHECK (next_index >= 0),
    total      INTEGER NOT NULL CHECK (total >= 0)
) WITHOUT ROWID;

-- The Windows releases Microsoft's release information pages list (feed windows-releases), handed to core/winrel, which answers
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

CREATE INDEX feeds_ioc_last_seen_idx ON feeds_ioc (last_seen);

CREATE INDEX feeds_ioc_source_src_idx ON feeds_ioc_source (source_id);

CREATE INDEX feeds_fetch_log_source_idx ON feeds_fetch_log (source_id, started_at DESC);

CREATE INDEX feeds_distro_fix_cve_idx ON feeds_distro_fix (cve);

CREATE INDEX feeds_distro_fix_package_idx ON feeds_distro_fix (distro, package);

CREATE INDEX feeds_cve_published_idx ON feeds_cve (published);

CREATE INDEX feeds_cve_range_cve_idx ON feeds_cve_range (cve);

CREATE INDEX feeds_cve_range_product_idx ON feeds_cve_range (vendor, product, cpe);

CREATE INDEX feeds_kev_list_idx ON feeds_kev (list, date_added DESC, cve DESC);

CREATE INDEX feeds_kev_source_idx ON feeds_kev (source_id);

CREATE INDEX feeds_kev_announced_idx ON feeds_kev (announced_at, cve) WHERE announced_at IS NOT NULL;

CREATE INDEX feeds_signal_kind_idx ON feeds_signal (kind, qualifies, cve);

CREATE INDEX feeds_signal_source_idx ON feeds_signal (source, kind);
