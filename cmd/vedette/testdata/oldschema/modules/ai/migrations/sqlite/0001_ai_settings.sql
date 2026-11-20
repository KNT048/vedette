-- +goose Up
-- ai tables of slice 1 (docs/DATA_MODEL.md 4.9): profiles, job assignments and the one-row settings. Forward-only.
-- Only ai.Service writes them. The API key itself lives in core_secret (purpose ai_profile.api_key); key_last4 is copied here
-- when sealing because ai may not read core_secret (core owns it).

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
    daily_cap  INTEGER NOT NULL CHECK (daily_cap BETWEEN 1000 AND 5000000),
    created_at TEXT    NOT NULL CHECK (created_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    updated_at TEXT    NOT NULL CHECK (updated_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
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

INSERT INTO ai_assignment (job) VALUES
    ('explain-finding'), ('mitigation-config'), ('cve-news'), ('log-digest'), ('log-investigate'),
    ('ask-my-data'), ('weekly-report'), ('pdpl-assessment'), ('translate-advisory'), ('response-plan')
ON CONFLICT (job) DO NOTHING;

-- One row per configuration object: config {tier, daily_cap, redact_pii}, assign {internal_only}. A missing row means the default.
-- Later slices add keys (knowledge, memory, activity); Go validates each object before it is written (DATA_MODEL 5.5).
CREATE TABLE ai_setting (
    key        TEXT NOT NULL PRIMARY KEY CHECK (length(key) BETWEEN 1 AND 40),
    value      TEXT NOT NULL CHECK (json_valid(value)),
    updated_at TEXT NOT NULL CHECK (updated_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    updated_by TEXT NOT NULL CHECK (length(updated_by) > 0)
);
