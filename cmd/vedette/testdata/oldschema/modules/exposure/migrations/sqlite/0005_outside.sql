-- +goose Up
-- What the Internet sees (D-558, INV-21): the last answer of Shodan InternetDB about one of the box's own public IPs, asked only
-- when an administrator clicks. One row per target, replaced by the next check, gone with its target; the audit log keeps every
-- request that was sent. answer is {ports, hostnames, cpes, tags, vulns}, already limited and checked when it was read (INV-10):
-- it is Shodan's claim, never a finding of Vedette. Forward-only (DATA_MODEL 6, rule 1).
CREATE TABLE exp_outside (
    target_id  TEXT NOT NULL PRIMARY KEY REFERENCES exp_target (id) ON DELETE CASCADE,
    ip         TEXT NOT NULL CHECK (length(ip) BETWEEN 7 AND 15 AND ip NOT GLOB '*[^0-9.]*'),
    checked_at TEXT NOT NULL CHECK (checked_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    checked_by TEXT NOT NULL CHECK (length(checked_by) BETWEEN 1 AND 320),
    found      INTEGER NOT NULL CHECK (found IN (0, 1)),
    answer     TEXT NOT NULL CHECK (json_valid(answer) AND json_type(answer) = 'object')
);
