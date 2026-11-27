-- +goose Up
-- Per-release-line status from vendor-owned data (feeds line sources, content/catalog/line-sources.json). Add-only.
-- feeds_line_cve: a line source speaks about this CVE for this product (the CVE is "covered": a line it does not list is read by
-- the source's convention). stated_at is the day of the vendor's statement (YYYY-MM-DD), ref the vendor's advisory shown as proof.
CREATE TABLE feeds_line_cve (
    source_id TEXT NOT NULL REFERENCES feeds_source (id) ON DELETE CASCADE,
    product   TEXT NOT NULL CHECK (length(product) BETWEEN 1 AND 60),
    cve       TEXT NOT NULL CHECK (cve GLOB 'CVE-[0-9][0-9][0-9][0-9]-[0-9][0-9][0-9][0-9]*' AND length(cve) <= 32),
    stated_at TEXT NOT NULL CHECK (stated_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]'),
    ref       TEXT NOT NULL DEFAULT '' CHECK (length(ref) <= 500),
    PRIMARY KEY (source_id, product, cve)
) WITHOUT ROWID;
CREATE INDEX feeds_line_cve_cve_idx ON feeds_line_cve (cve);

-- feeds_line_status: what the vendor states about one release line ("22", "8", "10.0") for the CVE: affected (from introduced,
-- up to last_affected or before fixed), fixed, unaffected, or hidden (the status exists but is not public yet). explicit: the vendor
-- said it (0: a convention). platforms: the platforms the statement is limited to (a JSON array, "win32"), NULL for every platform.
CREATE TABLE feeds_line_status (
    source_id     TEXT    NOT NULL,
    product       TEXT    NOT NULL,
    cve           TEXT    NOT NULL,
    line          TEXT    NOT NULL CHECK (length(line) BETWEEN 1 AND 40),
    status        TEXT    NOT NULL CHECK (status IN ('affected', 'fixed', 'unaffected', 'hidden')),
    introduced    TEXT    NOT NULL DEFAULT '' CHECK (length(introduced) <= 100),
    last_affected TEXT    NOT NULL DEFAULT '' CHECK (length(last_affected) <= 100),
    fixed         TEXT    NOT NULL DEFAULT '' CHECK (length(fixed) <= 100),
    explicit      INTEGER NOT NULL CHECK (explicit IN (0, 1)),
    platforms     TEXT    CHECK (platforms IS NULL OR (json_valid(platforms) AND json_type(platforms) = 'array')),
    PRIMARY KEY (source_id, product, cve, line),
    FOREIGN KEY (source_id, product, cve) REFERENCES feeds_line_cve (source_id, product, cve) ON DELETE CASCADE
) WITHOUT ROWID;

-- feeds_line_support: when a release line of a product was released and until when its vendor assesses it for security flaws
-- (assessed_until; NULL: still assessed), its end of life and last release, per source. Dates YYYY-MM-DD.
CREATE TABLE feeds_line_support (
    product        TEXT NOT NULL CHECK (length(product) BETWEEN 1 AND 60),
    line           TEXT NOT NULL CHECK (length(line) BETWEEN 1 AND 40),
    source_id      TEXT NOT NULL REFERENCES feeds_source (id) ON DELETE CASCADE,
    released       TEXT NOT NULL CHECK (released GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]'),
    assessed_until TEXT CHECK (assessed_until IS NULL OR assessed_until GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]'),
    eol            TEXT CHECK (eol IS NULL OR eol GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]'),
    last_release   TEXT CHECK (last_release IS NULL OR last_release GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]'),
    PRIMARY KEY (product, line, source_id)
) WITHOUT ROWID;
