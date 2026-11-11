-- +goose Up
-- ai_memory, ai_memory_suggestion and ai_skill_state of slice 4b (docs/DATA_MODEL.md 4.9, S-AI-7, INV-8). Forward-only. Only ai.Service
-- writes them. Go checks every limit first and says why; the triggers are the second lock for the two counts, so no path that skips
-- the service can pass them. The switch "suggest_enabled" is the key `memory` of ai_setting (a missing row = off).

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

-- +goose StatementBegin
CREATE TRIGGER ai_memory_max BEFORE INSERT ON ai_memory
WHEN (SELECT COUNT(*) FROM ai_memory) >= 100
BEGIN
    SELECT RAISE(ABORT, 'ai_memory: at most 100 memories');
END;
-- +goose StatementEnd

-- What the AI proposes to remember. A row here is NOT memory and never reaches a prompt (INV-8): accept moves it into ai_memory,
-- reject deletes it.
CREATE TABLE ai_memory_suggestion (
    id         TEXT NOT NULL PRIMARY KEY CHECK (length(id) BETWEEN 1 AND 96),
    text       TEXT NOT NULL CHECK (length(text) BETWEEN 3 AND 300),
    created_at TEXT NOT NULL CHECK (created_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    evidence   TEXT NOT NULL CHECK (length(evidence) BETWEEN 1 AND 200)
);

-- +goose StatementBegin
CREATE TRIGGER ai_memory_suggestion_max BEFORE INSERT ON ai_memory_suggestion
WHEN (SELECT COUNT(*) FROM ai_memory_suggestion) >= 50
BEGIN
    SELECT RAISE(ABORT, 'ai_memory_suggestion: at most 50 waiting suggestions');
END;
-- +goose StatementEnd

-- The switch of each product skill. The list of skills is in code; a skill with no row is on.
CREATE TABLE ai_skill_state (
    id      TEXT    NOT NULL PRIMARY KEY CHECK (length(id) BETWEEN 1 AND 40),
    enabled INTEGER NOT NULL CHECK (enabled IN (0, 1))
);
