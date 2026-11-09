-- +goose Up
-- The Ignored list (D-79 (3), INV-14): public IPs a person removed and chose not to add again, for example the address of a
-- security gateway, a VPN exit or a mobile backup line that the box sometimes uses but that is not the company's.
-- The list only blocks: detection never adds these addresses and nothing scans them. Restoring one deletes its row, which
-- lets detection add the address again; it never creates or approves a target. Forward-only (DATA_MODEL 6, rule 1).
CREATE TABLE exp_ignored (
    value      TEXT NOT NULL PRIMARY KEY CHECK (length(value) BETWEEN 7 AND 15 AND value GLOB '[0-9]*.[0-9]*.[0-9]*.[0-9]*' AND value NOT GLOB '*[^0-9.]*'),
    ignored_by TEXT NOT NULL CHECK (length(ignored_by) BETWEEN 1 AND 320),
    ignored_at TEXT NOT NULL CHECK (ignored_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z')
);
