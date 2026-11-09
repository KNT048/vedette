-- +goose Up
-- Connections to devices and services (D-93, D-94; DATA_MODEL core_connection, core_connection_tool). The token, password or SSH
-- private key lives in core_secret (purpose core_connection); the connection row owns it and both go in one transaction.
-- Forward-only (DATA_MODEL 6, rule 1): there is deliberately no Down section.
-- key_fp (an addition to DATA_MODEL) holds the SHA-256 fingerprint of the PUBLIC half of an SSH key, so a list never decrypts anything.
-- pos (also an addition) keeps the tools in the order the kind offers them.

CREATE TABLE core_connection (
    id         TEXT    NOT NULL PRIMARY KEY CHECK (length(id) BETWEEN 1 AND 96),
    name       TEXT    NOT NULL UNIQUE COLLATE NOCASE CHECK (length(name) BETWEEN 1 AND 40),
    kind       TEXT    NOT NULL CHECK (kind IN ('http', 'ssh', 'netconf-restconf', 'automation', 'mcp-http')),
    target     TEXT    NOT NULL CHECK (length(target) BETWEEN 1 AND 2048),
    asset_id   TEXT    CHECK (asset_id IS NULL OR length(asset_id) BETWEEN 1 AND 96),
    auth_type  TEXT    NOT NULL CHECK (auth_type IN ('none', 'token', 'basic', 'ssh-key')),
    username   TEXT    CHECK (username IS NULL OR length(username) BETWEEN 1 AND 64),
    secret_id  TEXT    REFERENCES core_secret (id),
    key_fp     TEXT    CHECK (key_fp IS NULL OR length(key_fp) BETWEEN 8 AND 100),
    pin        TEXT    CHECK (pin IS NULL OR length(pin) BETWEEN 1 AND 300),
    pin_seen   TEXT    CHECK (pin_seen IS NULL OR pin_seen GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    allow      TEXT    NOT NULL CHECK (json_valid(allow) AND json_type(allow) = 'array'),
    enabled    BOOLEAN NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    status     TEXT    NOT NULL DEFAULT 'untested' CHECK (status IN ('ok', 'error', 'untested')),
    last_test  TEXT    CHECK (last_test IS NULL OR last_test GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    updated_at TEXT    NOT NULL CHECK (updated_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    CHECK ((auth_type = 'none') = (secret_id IS NULL))
);

CREATE TABLE core_connection_tool (
    connection_id TEXT    NOT NULL REFERENCES core_connection (id) ON DELETE CASCADE,
    name          TEXT    NOT NULL CHECK (length(name) BETWEEN 1 AND 64),
    pos           INTEGER NOT NULL CHECK (pos >= 0),
    access        TEXT    NOT NULL CHECK (access IN ('read', 'write')),
    description   TEXT    NOT NULL CHECK (length(description) <= 200),
    enabled       BOOLEAN NOT NULL CHECK (enabled IN (0, 1)),
    PRIMARY KEY (connection_id, name)
) WITHOUT ROWID;
