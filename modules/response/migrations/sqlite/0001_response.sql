-- +goose Up
-- Response tables (modules/response/CONTRACT.md "Tables owned", docs/DATA_MODEL.md 4.11). Forward-only: no Down section.
-- Only response.Service writes them. Differences from the DATA_MODEL text are listed in docs/DECISIONS.md D-88:
-- items and approvals of a request are JSON columns of resp_actions (as the mock stores them), resp_block_entries and
-- resp_events are added, resp_log is append-only at the database level too (triggers).

-- One row, key 1: the execution switch and the safety envelope (JSON of response.Settings). A missing row = the defaults,
-- which keep the execution switch OFF (INV-7).
CREATE TABLE resp_settings (
    id         INTEGER NOT NULL PRIMARY KEY CHECK (id = 1),
    value      TEXT    NOT NULL CHECK (json_valid(value)),
    updated_at TEXT    NOT NULL
);

-- AI response plans (written by the AI job of part 13b; read by GET /response/plans).
CREATE TABLE resp_plans (
    id           TEXT NOT NULL PRIMARY KEY CHECK (length(id) BETWEEN 1 AND 96),
    finding_id   TEXT NOT NULL,
    cve          TEXT NOT NULL,
    asset_id     TEXT NOT NULL,
    asset_name   TEXT NOT NULL,
    generated_at TEXT NOT NULL,
    model        TEXT NOT NULL,
    profile      TEXT NOT NULL,
    path         TEXT NOT NULL,
    reads        TEXT NOT NULL CHECK (json_valid(reads)),
    steps        TEXT NOT NULL CHECK (json_valid(steps))
);
CREATE INDEX resp_plans_finding_ix ON resp_plans (finding_id);

-- One bundled request per rule run or AI proposal. items holds the actions with the checked values they were planned
-- with; approvals the people who approved. Statuses follow web/src/features/response/contract.ts.
CREATE TABLE resp_actions (
    seq                INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    id                 TEXT    NOT NULL UNIQUE CHECK (length(id) BETWEEN 1 AND 96),
    source             TEXT    NOT NULL CHECK (source IN ('ai', 'rule')),
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
CREATE INDEX resp_actions_status_ix ON resp_actions (status, requested_at);
CREATE INDEX resp_actions_proposal_ix ON resp_actions (proposal_id);
CREATE INDEX resp_actions_rule_ix ON resp_actions (rule_id, requested_at);

-- The action catalog. Built-in rows come from modules/response/data/action-templates.json (the templates are data,
-- D-58) and are refreshed from it when the service starts; enabled, ai_may_propose and connection_id belong to the user.
CREATE TABLE resp_catalog (
    id             TEXT    NOT NULL PRIMARY KEY CHECK (length(id) BETWEEN 1 AND 96),
    builtin        BOOLEAN NOT NULL CHECK (builtin IN (0, 1)),
    pack           TEXT    NOT NULL CHECK (length(pack) BETWEEN 1 AND 60),
    kind           TEXT    NOT NULL CHECK (kind IN ('box', 'device')),
    name           TEXT    NOT NULL CHECK (length(name) BETWEEN 1 AND 100),
    description    TEXT    NOT NULL,
    connection_id  TEXT,
    tool           TEXT,
    rollback_tool  TEXT,
    run            TEXT    NOT NULL CHECK (json_valid(run)),
    rollback       TEXT    NOT NULL CHECK (json_valid(rollback)),
    verify         TEXT    NOT NULL CHECK (json_valid(verify)),
    risk           TEXT    NOT NULL CHECK (risk IN ('low', 'medium', 'high')),
    enabled        BOOLEAN NOT NULL CHECK (enabled IN (0, 1)),
    ai_may_propose BOOLEAN NOT NULL CHECK (ai_may_propose IN (0, 1)),
    position       INTEGER NOT NULL
);

CREATE TABLE resp_rules (
    seq          INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    id           TEXT    NOT NULL UNIQUE CHECK (length(id) BETWEEN 1 AND 96),
    name         TEXT    NOT NULL,
    enabled      BOOLEAN NOT NULL CHECK (enabled IN (0, 1)),
    live         BOOLEAN NOT NULL DEFAULT 0 CHECK (live IN (0, 1)),
    trigger      TEXT    NOT NULL CHECK (trigger IN ('honeypot', 'ioc_connection', 'finding', 'unknown_device', 'log_threshold', 'new_port', 'schedule', 'manual')),
    match        TEXT    NOT NULL CHECK (match IN ('all', 'any')),
    conditions   TEXT    NOT NULL CHECK (json_valid(conditions)),
    actions      TEXT    NOT NULL CHECK (json_valid(actions)),
    pre_approved BOOLEAN NOT NULL DEFAULT 0 CHECK (pre_approved IN (0, 1)),
    max_per_hour INTEGER NOT NULL CHECK (max_per_hour BETWEEN 1 AND 100),
    schedule_min INTEGER CHECK (schedule_min IS NULL OR schedule_min BETWEEN 15 AND 10080),
    template_id  TEXT,
    last_fired   TEXT
);

-- The never-touch list the customer declared (the box's own addresses always count, they are not stored).
CREATE TABLE resp_allowlist (
    value TEXT NOT NULL PRIMARY KEY CHECK (length(value) BETWEEN 1 AND 260),
    label TEXT NOT NULL CHECK (length(label) <= 80)
);

-- The block list token (INV-17): only its SHA-256 is used to match a request; the token itself is sealed in core_secret
-- so the admin can copy the address again. One row, key 1.
CREATE TABLE resp_blocklist (
    id              INTEGER NOT NULL PRIMARY KEY CHECK (id = 1),
    token_hash      TEXT    NOT NULL CHECK (length(token_hash) = 64),
    secret_id       TEXT    NOT NULL REFERENCES core_secret (id),
    token_last4     TEXT    NOT NULL CHECK (length(token_last4) = 4),
    last_fetch_at   TEXT,
    last_fetch_from TEXT
);

-- The entries of the block list: executed blocklist_add items still in force. Added when the item runs, removed when
-- it is rolled back or its time to live ends, in the same transaction as the item's status.
CREATE TABLE resp_block_entries (
    value      TEXT NOT NULL,
    request_id TEXT NOT NULL,
    item_id    TEXT NOT NULL,
    source     TEXT NOT NULL,
    reason     TEXT NOT NULL,
    added_at   TEXT NOT NULL,
    expires_at TEXT,
    PRIMARY KEY (request_id, item_id)
);
CREATE INDEX resp_block_entries_value_ix ON resp_block_entries (value);

-- Approval links of part 13b (one-time tokens for email and Zalo OA). Created now so part 13b adds no table; part 1 never writes it.
CREATE TABLE resp_tokens (
    token_hash TEXT NOT NULL PRIMARY KEY CHECK (length(token_hash) = 64),
    action_id  TEXT NOT NULL,
    user_id    TEXT NOT NULL,
    address    TEXT NOT NULL,
    channel    TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    used_at    TEXT
);

-- Which rule already handled which event (INV-11 dedupe of one run).
CREATE TABLE resp_done (
    rule_id  TEXT NOT NULL,
    event_id TEXT NOT NULL,
    at       TEXT NOT NULL,
    PRIMARY KEY (rule_id, event_id)
);

-- AI notes and hints (part 13b).
CREATE TABLE resp_ai_notes (
    id         TEXT NOT NULL PRIMARY KEY,
    ts         TEXT NOT NULL,
    kind       TEXT NOT NULL CHECK (kind IN ('suggestion', 'digest')),
    title      TEXT NOT NULL,
    why        TEXT NOT NULL,
    confidence REAL NOT NULL,
    action_id  TEXT NOT NULL,
    target     TEXT NOT NULL,
    evidence   TEXT NOT NULL CHECK (json_valid(evidence))
);
CREATE TABLE resp_hints (
    id           TEXT NOT NULL PRIMARY KEY,
    ts           TEXT NOT NULL,
    kind         TEXT NOT NULL CHECK (kind IN ('rule', 'memory')),
    text         TEXT NOT NULL,
    from_request TEXT NOT NULL
);

-- Events the triggers watch (taken from the bus, kept so a rule can be simulated and the Events tab can show them).
-- processed = 0 until the evaluate job has run the rules on it.
CREATE TABLE resp_events (
    seq         INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    id          TEXT    NOT NULL UNIQUE CHECK (length(id) BETWEEN 1 AND 160),
    trigger     TEXT    NOT NULL CHECK (trigger IN ('honeypot', 'ioc_connection', 'finding', 'unknown_device', 'log_threshold', 'new_port', 'schedule', 'manual')),
    ts          TEXT    NOT NULL,
    summary     TEXT    NOT NULL,
    fields      TEXT    NOT NULL CHECK (json_valid(fields)),
    device_kind TEXT,
    asset_id    TEXT,
    finding_id  TEXT,
    cve         TEXT,
    processed   BOOLEAN NOT NULL DEFAULT 0 CHECK (processed IN (0, 1))
);
CREATE INDEX resp_events_trigger_ix ON resp_events (trigger, ts DESC);
CREATE INDEX resp_events_processed_ix ON resp_events (processed, seq);

-- The tamper-evident log (INV-19, D-48): append-only hash chain, one formula for every chain (core/chain).
CREATE TABLE resp_log (
    seq       INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    id        TEXT    NOT NULL UNIQUE CHECK (length(id) BETWEEN 1 AND 96),
    ts        TEXT    NOT NULL,
    kind      TEXT    NOT NULL CHECK (kind IN ('rule_fired', 'proposal', 'request', 'approved', 'rejected', 'executed', 'rolled_back', 'ttl_removed', 'refused', 'expired', 'failed', 'settings', 'emergency_stop', 'blocklist_token', 'dry_run', 'simulated', 'deduped', 'breaker', 'ai_note')),
    actor     TEXT    NOT NULL CHECK (length(actor) BETWEEN 1 AND 320),
    detail    TEXT    NOT NULL CHECK (length(detail) <= 1500),
    prev_hash TEXT    NOT NULL CHECK (length(prev_hash) = 64),
    hash      TEXT    NOT NULL CHECK (length(hash) = 64)
);

-- +goose StatementBegin
CREATE TRIGGER resp_log_no_update BEFORE UPDATE ON resp_log
BEGIN
    SELECT RAISE(ABORT, 'resp_log is append-only');
END;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TRIGGER resp_log_no_delete BEFORE DELETE ON resp_log
BEGIN
    SELECT RAISE(ABORT, 'resp_log is append-only');
END;
-- +goose StatementEnd

-- INSERT OR REPLACE deletes the row it conflicts with without firing the delete trigger (recursive_triggers is off), so a
-- row that would replace another one is refused here as well: the log is append-only in every SQL form.
-- +goose StatementBegin
CREATE TRIGGER resp_log_no_replace BEFORE INSERT ON resp_log
WHEN EXISTS (SELECT 1 FROM resp_log WHERE id = NEW.id OR seq = NEW.seq)
BEGIN
    SELECT RAISE(ABORT, 'resp_log is append-only');
END;
-- +goose StatementEnd
