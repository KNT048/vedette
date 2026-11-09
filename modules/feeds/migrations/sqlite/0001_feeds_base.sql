-- +goose Up
-- Feeds base (docs/DATA_MODEL.md 4.1, modules/feeds/CONTRACT.md "Tables owned"). Forward-only: no Down section.
-- Where DATA_MODEL and CONTRACT disagree the CONTRACT and the GUI mock win; the differences are listed in the
-- WP-20 report (pull state on feeds_source, feeds_fetch_log, derived IOC score and category, feeds_template).

-- One row per feed: the nine built-in feeds (merged from feeds.BuiltinSources() at start-up) and the custom ones.
-- The pull state (last_fetch .. catalog_version) lives on the same row (CONTRACT POST-1).
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
    catalog_version TEXT,
    CHECK (builtin = 1 OR parser IS NOT NULL),
    CHECK (secret_id IS NULL OR auth_type <> 'none')
);

CREATE UNIQUE INDEX feeds_source_name_uq ON feeds_source (lower(name));
CREATE INDEX feeds_source_kind_idx ON feeds_source (kind, enabled);

-- One row per exploited CVE. EPSS is kept only for CVEs that are here (DATA_MODEL open question 8).
-- A CVE has one owner: cisa-kev wins over a custom feed (source_id says who).
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
);

CREATE INDEX feeds_vuln_key_idx ON feeds_vuln (product_key);
CREATE INDEX feeds_vuln_date_idx ON feeds_vuln (date_added DESC, cve DESC);
CREATE INDEX feeds_vuln_source_idx ON feeds_vuln (source_id);

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

CREATE INDEX feeds_ioc_last_seen_idx ON feeds_ioc (last_seen);

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

CREATE INDEX feeds_ioc_source_src_idx ON feeds_ioc_source (source_id);

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

CREATE INDEX feeds_fetch_log_source_idx ON feeds_fetch_log (source_id, started_at DESC);

-- "This week, in short": the answer to each product's question.
CREATE TABLE feeds_weekly_answer (
    key         TEXT NOT NULL PRIMARY KEY CHECK (length(key) BETWEEN 1 AND 500),
    answer      TEXT NOT NULL CHECK (answer IN ('have', 'not_relevant')),
    user_id     TEXT NOT NULL CHECK (length(user_id) > 0),
    answered_at TEXT NOT NULL CHECK (answered_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z')
);
