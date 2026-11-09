-- +goose Up
-- Honeypot tables (docs/DATA_MODEL.md 4.7, names of the MANIFEST: hp_config, hp_hits, hp_decoys, hp_tokens, plus hp_trap
-- and hp_ignored_day). Forward-only (DATA_MODEL 6, rule 1): no Down section. Only honeypot.Service writes them.
-- Differences from DATA_MODEL 4.7 are listed in modules/honeypot/IMPACT.md (WP-14).

-- One row per configuration object: config {secondary_ip, hostname} | applied (the decoy IPs already handed to the host,
-- so a restart can remove stale ones) | tail (read position in the OpenCanary log). The value never holds a secret.
CREATE TABLE hp_config (
    key        TEXT NOT NULL PRIMARY KEY CHECK (key IN ('config', 'applied', 'tail')),
    value      TEXT NOT NULL CHECK (json_valid(value)),
    updated_at TEXT NOT NULL CHECK (updated_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    updated_by TEXT NOT NULL CHECK (length(updated_by) > 0)
) STRICT;

-- The five traps of INV-2, fixed rows.
CREATE TABLE hp_trap (
    service TEXT    NOT NULL PRIMARY KEY CHECK (service IN ('smb', 'rdp', 'ssh', 'mssql', 'http')),
    enabled INTEGER NOT NULL DEFAULT 0 CHECK (enabled IN (0, 1)),
    since   TEXT    CHECK (since IS NULL OR since GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z')
) STRICT;
INSERT INTO hp_trap (service) VALUES ('smb'), ('rdp'), ('ssh'), ('mssql'), ('http');

CREATE TABLE hp_decoys (
    id          TEXT    NOT NULL PRIMARY KEY CHECK (length(id) BETWEEN 1 AND 96),
    personality TEXT    NOT NULL CHECK (personality IN ('windows_fs', 'nas', 'printer', 'camera', 'linux')),
    name        TEXT    NOT NULL CHECK (length(name) BETWEEN 1 AND 15),
    ip          TEXT    NOT NULL UNIQUE CHECK (length(ip) BETWEEN 7 AND 15),
    enabled     INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    created_at  TEXT    NOT NULL CHECK (created_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z')
) STRICT;

-- The bait password of a credential token lives in core_secret (DATA_MODEL 5.4); the other types have none.
CREATE TABLE hp_tokens (
    id         TEXT NOT NULL PRIMARY KEY CHECK (length(id) BETWEEN 1 AND 96),
    type       TEXT NOT NULL CHECK (type IN ('file', 'credential', 'url', 'dns')),
    name       TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 64),
    value      TEXT NOT NULL CHECK (length(value) BETWEEN 1 AND 300),
    secret_id  TEXT REFERENCES core_secret (id),
    plant_at   TEXT NOT NULL CHECK (length(plant_at) BETWEEN 1 AND 120),
    created_at TEXT NOT NULL CHECK (created_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    CHECK ((type = 'credential') = (secret_id IS NOT NULL))
) STRICT;
CREATE UNIQUE INDEX hp_tokens_name_ux ON hp_tokens (type, lower(name));

-- Hits are evidence (FORBID-5): no endpoint edits or deletes them; only the retention job removes old rows.
-- src_asset_id is not stored: the source device is looked up by src_ip when read (INV-8). token_id is soft (a deleted
-- token keeps its history). conn_key makes one real connection one row and a repeated log line a no-op (POST-1).
CREATE TABLE hp_hits (
    id             TEXT    NOT NULL PRIMARY KEY CHECK (length(id) BETWEEN 1 AND 96),
    ts             TEXT    NOT NULL CHECK (ts GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    kind           TEXT    NOT NULL CHECK (kind IN ('service', 'token', 'scan')),
    service        TEXT    CHECK (service IS NULL OR service IN ('smb', 'rdp', 'ssh', 'mssql', 'http')),
    label          TEXT    NOT NULL CHECK (length(label) <= 200),
    port           INTEGER CHECK (port IS NULL OR port BETWEEN 1 AND 65535),
    src_ip         TEXT    NOT NULL CHECK (length(src_ip) BETWEEN 7 AND 15),
    source_ip      TEXT    GENERATED ALWAYS AS (src_ip) VIRTUAL,
    is_test        INTEGER NOT NULL DEFAULT 0 CHECK (is_test IN (0, 1)),
    excerpt        TEXT    NOT NULL CHECK (length(excerpt) <= 1000),
    trap_ip        TEXT    NOT NULL CHECK (length(trap_ip) <= 400),
    trap_hostname  TEXT    NOT NULL CHECK (length(trap_hostname) <= 200),
    token_id       TEXT    CHECK (token_id IS NULL OR length(token_id) <= 96),
    events         TEXT    NOT NULL DEFAULT '[]' CHECK (json_valid(events)),
    conn_key       TEXT    UNIQUE CHECK (conn_key IS NULL OR length(conn_key) = 64)
) STRICT;
CREATE INDEX hp_hits_ts_ix ON hp_hits (ts DESC);
CREATE INDEX hp_hits_src_ix ON hp_hits (src_ip);
CREATE INDEX hp_hits_token_ix ON hp_hits (token_id) WHERE token_id IS NOT NULL;

-- Hits from the scanner of the box itself that were ignored (INV-3), per day (30 days kept).
CREATE TABLE hp_ignored_day (
    day   TEXT    NOT NULL PRIMARY KEY CHECK (day GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]'),
    count INTEGER NOT NULL CHECK (count >= 0)
) STRICT;
