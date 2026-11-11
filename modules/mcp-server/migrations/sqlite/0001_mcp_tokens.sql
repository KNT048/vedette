-- +goose Up
-- Read-only MCP tokens (modules/mcp-server/CONTRACT.md INV-2..INV-4, D-231). Forward-only (DATA_MODEL 6, rule 1).
-- The token itself is never stored: token_hash is the SHA-256 (hex) of the whole token, as core_session does for session ids.
-- The token carries 128 random bits, so the hash in a backup cannot be turned back into a token. Revoking deletes the row.
CREATE TABLE mcp_tokens (
    id         TEXT NOT NULL PRIMARY KEY CHECK (length(id) BETWEEN 1 AND 96),
    name       TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 256),
    -- a JSON array of 1 to 3 distinct scopes out of assets, findings, feeds (checked by the service)
    scopes     TEXT NOT NULL CHECK (json_valid(scopes) AND json_type(scopes) = 'array' AND json_array_length(scopes) BETWEEN 1 AND 3),
    token_hash TEXT NOT NULL UNIQUE CHECK (length(token_hash) = 64),
    last4      TEXT NOT NULL CHECK (length(last4) = 4),
    created_at TEXT NOT NULL CHECK (created_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    last_used  TEXT CHECK (last_used IS NULL OR last_used GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z')
);
