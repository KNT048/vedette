-- +goose Up
-- ai_activity (the hash-chained log of every AI call, D-48), ai_result (what a job produced, cached by its inputs) and
-- ai_downgrade (automatic drops of the token level). docs/DATA_MODEL.md 4.9 and 5.3. Forward-only.

-- One row per AI call, appended in the same transaction as the result it belongs to. The chain head moves in that transaction
-- too (core_chain_head, chainhead.Advance). The content sent and received is never stored, only its hash (INV-17).
CREATE TABLE ai_activity (
    seq         INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    id          TEXT    NOT NULL UNIQUE CHECK (length(id) BETWEEN 1 AND 96),
    ts          TEXT    NOT NULL CHECK (ts GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    job         TEXT    NOT NULL CHECK (length(job) BETWEEN 1 AND 64),
    profile     TEXT    NOT NULL CHECK (length(profile) <= 160),
    model       TEXT    NOT NULL CHECK (length(model) <= 80),
    trigger     TEXT    NOT NULL CHECK (length(trigger) BETWEEN 1 AND 340),
    hooks       TEXT    NOT NULL CHECK (json_valid(hooks)),
    tools       TEXT    NOT NULL CHECK (json_valid(tools)),
    input_hash  TEXT    NOT NULL CHECK (length(input_hash) = 64),
    output_hash TEXT    NOT NULL CHECK (length(output_hash) = 64),
    summary     TEXT    NOT NULL CHECK (length(summary) <= 600),
    tokens_in   INTEGER NOT NULL CHECK (tokens_in >= 0),
    tokens_out  INTEGER NOT NULL CHECK (tokens_out >= 0),
    result      TEXT    NOT NULL CHECK (result IN ('ok', 'blocked_by_hook', 'fallback_used', 'error')),
    links       TEXT    CHECK (links IS NULL OR json_valid(links)),
    prev_hash   TEXT    NOT NULL CHECK (length(prev_hash) = 64),
    hash        TEXT    NOT NULL CHECK (length(hash) = 64)
);
CREATE INDEX ai_activity_ts ON ai_activity (ts);

-- No edit, and no replace that would delete a row without firing the delete trigger (recursive triggers are off). Retention
-- (slice 3) removes old rows in its own transaction together with the chain anchor and the head count.
-- +goose StatementBegin
CREATE TRIGGER ai_activity_no_update BEFORE UPDATE ON ai_activity
BEGIN
    SELECT RAISE(ABORT, 'ai_activity is append-only');
END;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TRIGGER ai_activity_no_replace BEFORE INSERT ON ai_activity
WHEN EXISTS (SELECT 1 FROM ai_activity WHERE id = NEW.id OR seq = NEW.seq)
BEGIN
    SELECT RAISE(ABORT, 'ai_activity is append-only');
END;
-- +goose StatementEnd

-- What a job produced. kind explain, news and log_digest are cached: one row per (kind, key, inputs_hash), so a changed
-- inventory or feed gives a new key and the old answer is not served for it.
CREATE TABLE ai_result (
    id          TEXT    NOT NULL PRIMARY KEY CHECK (length(id) BETWEEN 1 AND 96),
    kind        TEXT    NOT NULL CHECK (kind IN ('explain', 'news', 'ask', 'log_digest', 'weekly_summary', 'pdpl_summary')),
    key         TEXT    NOT NULL CHECK (length(key) BETWEEN 1 AND 600),
    inputs_hash TEXT    NOT NULL CHECK (length(inputs_hash) = 64),
    payload     TEXT    NOT NULL CHECK (json_valid(payload)),
    model       TEXT    NOT NULL CHECK (length(model) <= 80),
    profile     TEXT    NOT NULL CHECK (length(profile) <= 160),
    tokens_in   INTEGER NOT NULL CHECK (tokens_in >= 0),
    tokens_out  INTEGER NOT NULL CHECK (tokens_out >= 0),
    asked_by    TEXT    CHECK (asked_by IS NULL OR length(asked_by) <= 320),
    activity_id TEXT,   -- soft reference to ai_activity.id
    created_at  TEXT    NOT NULL CHECK (created_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z')
);
CREATE INDEX ai_result_lookup ON ai_result (kind, key, created_at DESC);
CREATE UNIQUE INDEX ai_result_once ON ai_result (kind, key, inputs_hash) WHERE kind IN ('explain', 'news', 'log_digest');

CREATE TABLE ai_downgrade (
    id        TEXT NOT NULL PRIMARY KEY CHECK (length(id) BETWEEN 1 AND 96),
    ts        TEXT NOT NULL CHECK (ts GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    from_tier TEXT NOT NULL CHECK (from_tier IN ('min', 'med', 'max')),
    to_tier   TEXT NOT NULL CHECK (to_tier IN ('min', 'med', 'max')),
    reason    TEXT NOT NULL CHECK (length(reason) BETWEEN 1 AND 300)
);
CREATE INDEX ai_downgrade_ts ON ai_downgrade (ts);
