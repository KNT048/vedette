-- +goose Up
-- Chain head (issue #17): the hash and row count of the newest row of each hash chain, written in the same
-- transaction as every append. Verification compares the table with it, so deleting the newest rows is caught
-- (core_chain_anchor only records where a pruned chain starts). count is the number of rows the chain holds now.
-- Forward-only (DATA_MODEL 6, rule 1): there is deliberately no Down section.

CREATE TABLE core_chain_head (
    chain      TEXT    NOT NULL PRIMARY KEY CHECK (chain IN ('core_audit', 'ai_activity', 'resp_log')),
    last_hash  TEXT    NOT NULL CHECK (length(last_hash) = 64),
    count      INTEGER NOT NULL CHECK (count >= 0),
    updated_at TEXT    NOT NULL CHECK (updated_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z')
);

-- core_audit may already hold rows (written before this migration): record their head.
INSERT INTO core_chain_head (chain, last_hash, count, updated_at)
SELECT 'core_audit', (SELECT hash FROM core_audit ORDER BY seq DESC LIMIT 1), (SELECT count(*) FROM core_audit),
       strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
WHERE EXISTS (SELECT 1 FROM core_audit);
