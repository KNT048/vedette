-- +goose Up
-- ai_rule, ai_hook and ai_hook_state of slice 4a (docs/DATA_MODEL.md 4.9, S-AI-7): the rules a company adds to every prompt, its own
-- hooks, and the switches of the built-in hooks. Forward-only. Only ai.Service writes them. Go checks every limit first and says why;
-- the triggers are the second lock for the two counts, so no path that skips the service can pass them.

-- Customer rules (the four built-in rules live in code). jobs is a JSON array of job names; [] = every job. Order = creation order (rowid).
CREATE TABLE ai_rule (
    id         TEXT    NOT NULL PRIMARY KEY CHECK (length(id) BETWEEN 1 AND 96),
    text       TEXT    NOT NULL CHECK (length(text) BETWEEN 3 AND 300),
    jobs       TEXT    NOT NULL CHECK (json_valid(jobs) AND json_type(jobs) = 'array'),
    enabled    INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    created_at TEXT    NOT NULL CHECK (created_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    updated_at TEXT    NOT NULL CHECK (updated_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z')
);

-- +goose StatementBegin
CREATE TRIGGER ai_rule_max BEFORE INSERT ON ai_rule
WHEN (SELECT COUNT(*) FROM ai_rule) >= 30
BEGIN
    SELECT RAISE(ABORT, 'ai_rule: at most 30 rules');
END;
-- +goose StatementEnd

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

-- +goose StatementBegin
CREATE TRIGGER ai_hook_max BEFORE INSERT ON ai_hook
WHEN (SELECT COUNT(*) FROM ai_hook) >= 30
BEGIN
    SELECT RAISE(ABORT, 'ai_hook: at most 30 custom hooks');
END;
-- +goose StatementEnd

-- The switches of the three built-in hooks, loaded here. write-approval is locked on: the CHECK refuses a row that turns it off.
-- block-pii is also the "redact_pii" of /ai/config: one switch, one row.
CREATE TABLE ai_hook_state (
    builtin_id TEXT    NOT NULL PRIMARY KEY CHECK (builtin_id IN ('block-pii', 'security-only', 'write-approval')),
    enabled    INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    CHECK (builtin_id <> 'write-approval' OR enabled = 1)
);

INSERT INTO ai_hook_state (builtin_id, enabled) VALUES ('block-pii', 1), ('security-only', 1), ('write-approval', 1)
ON CONFLICT (builtin_id) DO NOTHING;
