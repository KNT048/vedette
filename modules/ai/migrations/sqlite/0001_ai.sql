-- +goose Up
-- The whole schema of the ai module. It is edited in place until the first public release; docs/SCHEMA.sql
-- shows the schema of every module together. Forward-only: there is no Down section.

CREATE TABLE ai_profile (
    id         TEXT    NOT NULL PRIMARY KEY CHECK (length(id) BETWEEN 1 AND 96),
    name       TEXT    NOT NULL CHECK (length(name) BETWEEN 1 AND 160),
    name_key   TEXT    NOT NULL UNIQUE CHECK (length(name_key) BETWEEN 1 AND 320),  -- lower-case name: unique in every letter case
    kind       TEXT    NOT NULL CHECK (kind IN ('anthropic', 'openai', 'gemini', 'openai-compatible', 'custom')),
    api_style  TEXT    NOT NULL CHECK (api_style IN ('openai', 'anthropic', 'gemini')),
    base_url   TEXT    NOT NULL CHECK (length(base_url) BETWEEN 1 AND 500),
    model      TEXT    NOT NULL CHECK (length(model) BETWEEN 1 AND 80),
    secret_id  TEXT    REFERENCES core_secret (id),
    key_last4  TEXT    CHECK (key_last4 IS NULL OR length(key_last4) = 4),
    location   TEXT    NOT NULL CHECK (location IN ('internal', 'cloud')),
    created_at TEXT    NOT NULL CHECK (created_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    updated_at TEXT    NOT NULL CHECK (updated_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'), monthly_budget INTEGER NOT NULL DEFAULT 6000000 CHECK (monthly_budget BETWEEN 1000 AND 150000000),
    -- a cloud profile always has a key; an internal one may have none (INV-1)
    CHECK (location = 'internal' OR secret_id IS NOT NULL),
    CHECK ((secret_id IS NULL) = (key_last4 IS NULL))
);

-- Ten fixed rows, one per AI job (INV-2), loaded here and never inserted or deleted by code.
CREATE TABLE ai_assignment (
    job                 TEXT NOT NULL PRIMARY KEY CHECK (job IN ('explain-finding', 'mitigation-config', 'cve-news', 'log-digest', 'log-investigate', 'ask-my-data', 'weekly-report', 'pdpl-assessment', 'translate-advisory', 'response-plan')),
    primary_profile_id  TEXT REFERENCES ai_profile (id) ON DELETE SET NULL,
    fallback_profile_id TEXT REFERENCES ai_profile (id) ON DELETE SET NULL,
    CHECK (fallback_profile_id IS NULL OR primary_profile_id IS NOT NULL),
    CHECK (fallback_profile_id IS NULL OR fallback_profile_id <> primary_profile_id)
);

-- One row per configuration object: config {tier, daily_cap, redact_pii}, assign {internal_only}. A missing row means the default.
-- Later slices add keys (knowledge, memory, activity); Go validates each object before it is written (DATA_MODEL 5.5).
CREATE TABLE ai_setting (
    key        TEXT NOT NULL PRIMARY KEY CHECK (length(key) BETWEEN 1 AND 40),
    value      TEXT NOT NULL CHECK (json_valid(value)),
    updated_at TEXT NOT NULL CHECK (updated_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    updated_by TEXT NOT NULL CHECK (length(updated_by) > 0)
);

CREATE TABLE ai_activity (
    seq         INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    id          TEXT    NOT NULL UNIQUE CHECK (length(id) BETWEEN 1 AND 96),
    ts          TEXT    NOT NULL CHECK (ts GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    job         TEXT    NOT NULL CHECK (length(job) BETWEEN 1 AND 64),
    profile     TEXT    NOT NULL CHECK (length(profile) <= 160),
    profile_id  TEXT    CHECK (profile_id IS NULL OR length(profile_id) <= 96),  -- not part of the hash: it only tells the meter whose tokens these are, whatever the profile is called later
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
, outcome TEXT CHECK (outcome IS NULL OR outcome IN ('capped', 'not_sent')), stop TEXT CHECK (stop IS NULL OR stop IN ('end', 'max_tokens', 'tool_use', 'other')), retried INTEGER NOT NULL DEFAULT 0 CHECK (retried IN (0, 1)));

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

CREATE TABLE ai_downgrade (
    id        TEXT NOT NULL PRIMARY KEY CHECK (length(id) BETWEEN 1 AND 96),
    ts        TEXT NOT NULL CHECK (ts GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    from_tier TEXT NOT NULL CHECK (from_tier IN ('min', 'med', 'max')),
    to_tier   TEXT NOT NULL CHECK (to_tier IN ('min', 'med', 'max')),
    reason    TEXT NOT NULL CHECK (length(reason) BETWEEN 1 AND 300)
);

-- Customer rules (the four built-in rules live in code). jobs is a JSON array of job names; [] = every job. Order = creation order (rowid).
CREATE TABLE ai_rule (
    id         TEXT    NOT NULL PRIMARY KEY CHECK (length(id) BETWEEN 1 AND 96),
    text       TEXT    NOT NULL CHECK (length(text) BETWEEN 3 AND 300),
    jobs       TEXT    NOT NULL CHECK (json_valid(jobs) AND json_type(jobs) = 'array'),
    enabled    INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    created_at TEXT    NOT NULL CHECK (created_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    updated_at TEXT    NOT NULL CHECK (updated_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z')
);

-- Customer hooks. The pattern is compiled by Go (RE2) when saved and again on load; the checks here are only the shape.
CREATE TABLE ai_hook (
    id         TEXT    NOT NULL PRIMARY KEY CHECK (length(id) BETWEEN 1 AND 96),
    name       TEXT    NOT NULL CHECK (length(name) BETWEEN 1 AND 40),
    name_key   TEXT    NOT NULL UNIQUE CHECK (length(name_key) BETWEEN 1 AND 80),  -- lower-case name: unique in every letter case
    "when"     TEXT    NOT NULL CHECK ("when" IN ('before_ai', 'after_ai', 'before_tool')),
    match_type TEXT    NOT NULL CHECK (match_type IN ('keywords', 'regex')),
    pattern    TEXT    NOT NULL CHECK (length(pattern) BETWEEN 1 AND 200),
    action     TEXT    NOT NULL CHECK (action IN ('block', 'mask', 'approve')),
    message    TEXT    NOT NULL CHECK (length(message) BETWEEN 3 AND 200),
    enabled    INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    created_at TEXT    NOT NULL CHECK (created_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    updated_at TEXT    NOT NULL CHECK (updated_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z')
);

-- The switches of the three built-in hooks, loaded here. write-approval is locked on: the CHECK refuses a row that turns it off.
-- block-pii is also the "redact_pii" of /ai/config: one switch, one row.
CREATE TABLE ai_hook_state (
    builtin_id TEXT    NOT NULL PRIMARY KEY CHECK (builtin_id IN ('block-pii', 'security-only', 'write-approval')),
    enabled    INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    CHECK (builtin_id <> 'write-approval' OR enabled = 1)
);

-- What an administrator told the box about the network: typed by hand (source user) or accepted from a suggestion (source ai).
-- Only an enabled row reaches a prompt, as fenced data. Order = newest first (rowid).
CREATE TABLE ai_memory (
    id           TEXT    NOT NULL PRIMARY KEY CHECK (length(id) BETWEEN 1 AND 96),
    text         TEXT    NOT NULL CHECK (length(text) BETWEEN 3 AND 300),
    source       TEXT    NOT NULL CHECK (source IN ('ai', 'user')),
    created_at   TEXT    NOT NULL CHECK (created_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    last_used_at TEXT    CHECK (last_used_at IS NULL OR last_used_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    enabled      INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1))
);

-- What the AI proposes to remember. A row here is NOT memory and never reaches a prompt (INV-8): accept moves it into ai_memory,
-- reject deletes it.
CREATE TABLE ai_memory_suggestion (
    id         TEXT NOT NULL PRIMARY KEY CHECK (length(id) BETWEEN 1 AND 96),
    text       TEXT NOT NULL CHECK (length(text) BETWEEN 3 AND 300),
    created_at TEXT NOT NULL CHECK (created_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    evidence   TEXT NOT NULL CHECK (length(evidence) BETWEEN 1 AND 200)
);

-- Text an administrator rejected, as a SHA-256 digest, for 30 days: SuggestMemory does not bring it back at once. Purged by Go on every reject
-- and every suggestion.
CREATE TABLE ai_memory_rejected (
    digest      TEXT NOT NULL PRIMARY KEY CHECK (length(digest) = 64),
    rejected_at TEXT NOT NULL CHECK (rejected_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z')
);

-- The switch of each product skill. The list of skills is in code; a skill with no row is on.
CREATE TABLE ai_skill_state (
    id      TEXT    NOT NULL PRIMARY KEY CHECK (length(id) BETWEEN 1 AND 40),
    enabled INTEGER NOT NULL CHECK (enabled IN (0, 1))
);

-- One uploaded document. status: uploading (received, waiting for the indexer), indexing (being read), ready. chunks is null until
-- the document is ready; a document that could not be read, or has no text in it, is ready with 0 chunks (the audit row says why).
-- jobs is a JSON array of job ids; [] means every job (only the jobs that carry internal data ever read it, INV-3).
CREATE TABLE ai_knowledge_doc (
    id          TEXT    NOT NULL PRIMARY KEY CHECK (length(id) BETWEEN 1 AND 96),
    name        TEXT    NOT NULL CHECK (length(name) BETWEEN 1 AND 120),
    size        INTEGER NOT NULL CHECK (size BETWEEN 1 AND 10485760),
    status      TEXT    NOT NULL CHECK (status IN ('uploading', 'indexing', 'ready')),
    chunks      INTEGER CHECK (chunks IS NULL OR chunks >= 0),
    jobs        TEXT    NOT NULL CHECK (json_valid(jobs) AND json_type(jobs) = 'array'),
    uploaded_at TEXT    NOT NULL CHECK (uploaded_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    CHECK ((status = 'ready') = (chunks IS NOT NULL))
);

-- The text of a document in pieces of about 3200 bytes (customer data: exported like memory, deleted with the document).
CREATE TABLE ai_knowledge_chunk (
    id     INTEGER NOT NULL PRIMARY KEY,
    doc_id TEXT    NOT NULL REFERENCES ai_knowledge_doc (id) ON DELETE CASCADE,
    seq    INTEGER NOT NULL CHECK (seq >= 1),
    text   TEXT    NOT NULL CHECK (length(text) BETWEEN 1 AND 4000),
    UNIQUE (doc_id, seq)
);

-- The index of the chunks: external content, so the text is stored once. unicode61 with remove_diacritics 2 makes "tuong" find
-- "Tường". The triggers keep it in step with the chunk table, in the same transaction as every insert and delete.
CREATE VIRTUAL TABLE ai_knowledge_chunk_fts USING fts5 (text, content = 'ai_knowledge_chunk', content_rowid = 'id', tokenize = 'unicode61 remove_diacritics 2');

-- ai_read of slice 7 (D-311, D-119): one row per read the box itself made through a connection read tool (core/conn/read), written by
-- the tool runner after the read answered, never from text the model produced. response looks a row up by id as config_read evidence
-- of an AI proposal; only rows at most 24 hours old count. Rows older than that are removed when a new read is recorded, and at most
-- the newest 500 are kept. The output of the read is not stored: only which connection and which tool, and when. Forward-only.
CREATE TABLE ai_read (
    id              TEXT NOT NULL PRIMARY KEY CHECK (length(id) BETWEEN 1 AND 96),
    ts              TEXT NOT NULL CHECK (ts GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    connection_id   TEXT NOT NULL CHECK (length(connection_id) BETWEEN 1 AND 96),
    connection_name TEXT NOT NULL CHECK (length(connection_name) <= 60),
    tool            TEXT NOT NULL CHECK (length(tool) BETWEEN 1 AND 60),
    job             TEXT NOT NULL CHECK (length(job) BETWEEN 1 AND 32)
);

CREATE INDEX ai_activity_ts ON ai_activity (ts);

CREATE INDEX ai_result_lookup ON ai_result (kind, key, created_at DESC);

CREATE UNIQUE INDEX ai_result_once ON ai_result (kind, key, inputs_hash) WHERE kind IN ('explain', 'news', 'log_digest');

CREATE INDEX ai_downgrade_ts ON ai_downgrade (ts);

CREATE INDEX ai_read_ts ON ai_read (ts);

INSERT INTO ai_assignment (job) VALUES ('explain-finding');
INSERT INTO ai_assignment (job) VALUES ('mitigation-config');
INSERT INTO ai_assignment (job) VALUES ('cve-news');
INSERT INTO ai_assignment (job) VALUES ('log-digest');
INSERT INTO ai_assignment (job) VALUES ('log-investigate');
INSERT INTO ai_assignment (job) VALUES ('ask-my-data');
INSERT INTO ai_assignment (job) VALUES ('weekly-report');
INSERT INTO ai_assignment (job) VALUES ('pdpl-assessment');
INSERT INTO ai_assignment (job) VALUES ('translate-advisory');
INSERT INTO ai_assignment (job) VALUES ('response-plan');

INSERT INTO ai_hook_state (builtin_id) VALUES ('block-pii');
INSERT INTO ai_hook_state (builtin_id) VALUES ('security-only');
INSERT INTO ai_hook_state (builtin_id) VALUES ('write-approval');

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

-- +goose StatementBegin
CREATE TRIGGER ai_rule_max BEFORE INSERT ON ai_rule
WHEN (SELECT COUNT(*) FROM ai_rule) >= 30
BEGIN
    SELECT RAISE(ABORT, 'ai_rule: at most 30 rules');
END;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TRIGGER ai_hook_max BEFORE INSERT ON ai_hook
WHEN (SELECT COUNT(*) FROM ai_hook) >= 30
BEGIN
    SELECT RAISE(ABORT, 'ai_hook: at most 30 custom hooks');
END;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TRIGGER ai_memory_max BEFORE INSERT ON ai_memory
WHEN (SELECT COUNT(*) FROM ai_memory) >= 100
BEGIN
    SELECT RAISE(ABORT, 'ai_memory: at most 100 memories');
END;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TRIGGER ai_memory_suggestion_max BEFORE INSERT ON ai_memory_suggestion
WHEN (SELECT COUNT(*) FROM ai_memory_suggestion) >= 50
BEGIN
    SELECT RAISE(ABORT, 'ai_memory_suggestion: at most 50 waiting suggestions');
END;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TRIGGER ai_knowledge_doc_max BEFORE INSERT ON ai_knowledge_doc
WHEN (SELECT COUNT(*) FROM ai_knowledge_doc) >= 50
BEGIN
    SELECT RAISE(ABORT, 'ai_knowledge_doc: at most 50 documents');
END;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TRIGGER ai_knowledge_chunk_ai AFTER INSERT ON ai_knowledge_chunk
BEGIN
    INSERT INTO ai_knowledge_chunk_fts (rowid, text) VALUES (new.id, new.text);
END;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TRIGGER ai_knowledge_chunk_ad AFTER DELETE ON ai_knowledge_chunk
BEGIN
    INSERT INTO ai_knowledge_chunk_fts (ai_knowledge_chunk_fts, rowid, text) VALUES ('delete', old.id, old.text);
END;
-- +goose StatementEnd
