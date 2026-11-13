-- +goose Up
-- D-509 (W1-16, S-RESP-3): a person asks for a response from an incident, so a request has a third source, "person". SQLite cannot
-- change a CHECK, so the table is rebuilt with the same columns and indexes. Forward-only (DATA_MODEL 6, rule 1).
CREATE TABLE resp_actions_new (
    seq                INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    id                 TEXT    NOT NULL UNIQUE CHECK (length(id) BETWEEN 1 AND 96),
    source             TEXT    NOT NULL CHECK (source IN ('ai', 'rule', 'person')),
    proposal_id        TEXT    NOT NULL,
    rule_id            TEXT,
    rule_name          TEXT,
    trigger            TEXT,
    trigger_summary    TEXT,
    finding_id         TEXT,
    cve                TEXT,
    asset_id           TEXT,
    asset_name         TEXT    NOT NULL,
    title              TEXT    NOT NULL,
    risk               TEXT    NOT NULL CHECK (risk IN ('low', 'medium', 'high')),
    status             TEXT    NOT NULL CHECK (status IN ('pending', 'approved', 'rejected', 'expired', 'executed', 'failed', 'rolled_back')),
    requested_at       TEXT    NOT NULL,
    expires_at         TEXT    NOT NULL,
    decided_at         TEXT,
    requires_approvals INTEGER NOT NULL CHECK (requires_approvals IN (1, 2)),
    two_because        TEXT,
    approvals          TEXT    NOT NULL DEFAULT '[]' CHECK (json_valid(approvals)),
    sent_to            TEXT    NOT NULL DEFAULT '[]' CHECK (json_valid(sent_to)),
    note               TEXT,
    pre_approved       BOOLEAN NOT NULL DEFAULT 0 CHECK (pre_approved IN (0, 1)),
    ai                 TEXT    CHECK (ai IS NULL OR json_valid(ai)),
    items              TEXT    NOT NULL CHECK (json_valid(items))
);
INSERT INTO resp_actions_new (seq, id, source, proposal_id, rule_id, rule_name, trigger, trigger_summary, finding_id, cve, asset_id, asset_name, title, risk, status, requested_at, expires_at, decided_at, requires_approvals, two_because, approvals, sent_to, note, pre_approved, ai, items)
    SELECT seq, id, source, proposal_id, rule_id, rule_name, trigger, trigger_summary, finding_id, cve, asset_id, asset_name, title, risk, status, requested_at, expires_at, decided_at, requires_approvals, two_because, approvals, sent_to, note, pre_approved, ai, items FROM resp_actions;
-- Keep the AUTOINCREMENT high-water mark: the copy only raises the new table's counter to the largest seq still there, so the seq of
-- requests deleted at the top would be given out again.
INSERT INTO sqlite_sequence (name, seq) SELECT 'resp_actions_new', 0 WHERE NOT EXISTS (SELECT 1 FROM sqlite_sequence WHERE name = 'resp_actions_new');
UPDATE sqlite_sequence SET seq = MAX(seq, COALESCE((SELECT seq FROM sqlite_sequence WHERE name = 'resp_actions'), 0)) WHERE name = 'resp_actions_new';
DROP TABLE resp_actions;
ALTER TABLE resp_actions_new RENAME TO resp_actions;
CREATE INDEX resp_actions_status_ix ON resp_actions (status, requested_at);
CREATE INDEX resp_actions_proposal_ix ON resp_actions (proposal_id);
CREATE INDEX resp_actions_rule_ix ON resp_actions (rule_id, requested_at);
