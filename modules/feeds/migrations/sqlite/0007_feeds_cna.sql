-- +goose Up
-- feeds_cna: the CVE Program's list of CNAs (built-in feed cve-cna-list), replaced whole by each good pull. short_name is a CVE
-- record's assignerShortName in lower case (a short name two CNAs share is left out), organization the CNA's organization name as the
-- list writes it, may_be_vendor whether the list types it as a vendor or an open-source project and its scope does not take the
-- reports of other CNAs' products (cnaMayBeVendor). Read with the ranges (readRanges) while the feed's last good pull is under 30 days
-- old: a CNA whose organization name is the vendor of a record's row is the vendor's own CNA (ownCNA). No contact data is kept.
-- Add-only.
CREATE TABLE feeds_cna (
    short_name    TEXT    NOT NULL PRIMARY KEY CHECK (length(short_name) BETWEEN 1 AND 64 AND short_name = lower(short_name)),
    source_id     TEXT    NOT NULL REFERENCES feeds_source (id) ON DELETE CASCADE,
    organization  TEXT    NOT NULL CHECK (length(organization) BETWEEN 1 AND 200),
    may_be_vendor INTEGER NOT NULL CHECK (may_be_vendor IN (0, 1))
) WITHOUT ROWID;
