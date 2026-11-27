-- +goose Up
-- One reading by the AI of what the vendor states about one CVE for one release line of a product: affected, fixed (in fixed_in),
-- not affected, or unsure. The box fetched the page itself; the AI read its text as data and answered by schema; the box then found
-- the quote word for word in the text it fetched (quote_found) and kept a version bound only when the quote names it (a bound the
-- quote does not name is NULL). Keyed by the CVE, the product, the release line, the CVE record's stamp (record_hash) and the cited
-- page's text (page_hash), so the next match applies it to every device and version on that line and a changed record or page is
-- read again. Only the newest reading of a (cve, product_key, line) is kept; a reading a person rejected stays (rejected_by), so the
-- same page is never applied again. seen_at is the last fetch that found the same page text. No device data: shared by every
-- device on the line. Forward-only: there is no Down section.
CREATE TABLE fnd_line_statement (
    statement_key TEXT    NOT NULL PRIMARY KEY CHECK (length(statement_key) = 64 AND statement_key NOT GLOB '*[^0-9a-f]*'),
    cve           TEXT    NOT NULL CHECK (cve GLOB 'CVE-[0-9][0-9][0-9][0-9]-[0-9][0-9][0-9][0-9]*' AND length(cve) <= 32),
    product_key   TEXT    NOT NULL CHECK (length(product_key) BETWEEN 1 AND 300),
    line          TEXT    NOT NULL CHECK (length(line) BETWEEN 1 AND 200),
    stated_line   TEXT    NOT NULL DEFAULT '' CHECK (length(stated_line) <= 200),
    record_hash   TEXT    NOT NULL CHECK (length(record_hash) = 64),
    page_hash     TEXT    NOT NULL CHECK (length(page_hash) = 64),
    status        TEXT    NOT NULL CHECK (status IN ('affected', 'fixed', 'not_affected', 'unsure')),
    introduced    TEXT    CHECK (introduced IS NULL OR length(introduced) BETWEEN 1 AND 100),
    fixed_in      TEXT    CHECK (fixed_in IS NULL OR length(fixed_in) BETWEEN 1 AND 100),
    last_affected TEXT    CHECK (last_affected IS NULL OR length(last_affected) BETWEEN 1 AND 100),
    reason        TEXT    NOT NULL DEFAULT '' CHECK (length(reason) <= 600),
    quote         TEXT    NOT NULL DEFAULT '' CHECK (length(quote) <= 400),
    url           TEXT    NOT NULL DEFAULT '' CHECK (length(url) <= 2000),
    host          TEXT    NOT NULL DEFAULT '' CHECK (length(host) <= 255),
    vendor_page   INTEGER NOT NULL CHECK (vendor_page IN (0, 1)),
    quote_found   INTEGER NOT NULL CHECK (quote_found IN (0, 1)),
    model         TEXT    NOT NULL CHECK (length(model) BETWEEN 1 AND 80),
    profile       TEXT    NOT NULL CHECK (length(profile) BETWEEN 1 AND 160),
    activity_id   TEXT    CHECK (activity_id IS NULL OR length(activity_id) <= 96),
    asked_by      TEXT    NOT NULL CHECK (length(asked_by) BETWEEN 1 AND 320),
    asked_at      TEXT    NOT NULL CHECK (asked_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    seen_at       TEXT    NOT NULL CHECK (seen_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    rejected_by   TEXT    CHECK (rejected_by IS NULL OR length(rejected_by) BETWEEN 1 AND 320),
    rejected_at   TEXT    CHECK (rejected_at IS NULL OR rejected_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    CHECK ((rejected_by IS NULL) = (rejected_at IS NULL)),
    CHECK (status <> 'fixed' OR fixed_in IS NOT NULL OR last_affected IS NOT NULL)
);

CREATE UNIQUE INDEX fnd_line_statement_identity_uq ON fnd_line_statement (cve, product_key, line, record_hash, page_hash);

CREATE INDEX fnd_line_statement_cve_ix ON fnd_line_statement (cve, product_key);
