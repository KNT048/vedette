-- +goose Up
-- The whole schema of the honeypot module. It is edited in place until the first public release; docs/SCHEMA.sql
-- shows the schema of every module together. Forward-only: there is no Down section.

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

-- Hits from the scanner of the box itself that were ignored (INV-3), per day (30 days kept).
CREATE TABLE hp_ignored_day (
    day   TEXT    NOT NULL PRIMARY KEY CHECK (day GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]'),
    count INTEGER NOT NULL CHECK (count >= 0)
) STRICT;

-- D-466: a Trap IP is a profile (name, address, preset, vendor, its own services). One table replaces the secondary IP (hp_config key
-- "config"), the five box-wide trap switches (hp_trap) and the decoy personalities (hp_decoys). Forward-only: no Down section.
-- No address answers a port after this migration that it did not answer before: the secondary IP keeps the traps that were on; a decoy
-- keeps the services of its preset that were on (a decoy used to answer every trap that was on, which D-466 ends); a profile left with
-- nothing that was on keeps its preset's services and is switched off. Vendor is NULL, so every address keeps the MAC it has. Hits stay.
CREATE TABLE hp_trap_ips (
    id         TEXT    NOT NULL PRIMARY KEY CHECK (length(id) BETWEEN 1 AND 96),
    name       TEXT    NOT NULL CHECK (length(name) BETWEEN 1 AND 15),
    ip         TEXT    NOT NULL UNIQUE CHECK (length(ip) BETWEEN 7 AND 15),
    preset     TEXT    NOT NULL CHECK (preset IN ('file_server', 'nas', 'printer', 'camera', 'linux', 'database', 'custom')),
    vendor     TEXT    CHECK (vendor IS NULL OR length(vendor) BETWEEN 1 AND 32),
    services   TEXT    NOT NULL CHECK (json_valid(services) AND json_type(services) = 'array'),
    enabled    INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    -- The last MAC the host gave the address (it derives it from the address and the vendor, so it is the same next time): a device
    -- row carrying it is a ghost of this Trap IP's own frames, never a machine on the address (B2 lab). NULL until the host says.
    mac        TEXT    CHECK (mac IS NULL OR length(mac) = 17),
    -- When the address last became a Trap IP that is on (added, switched on, moved); NULL = created_at. A device row the inventory
    -- made at the address or of its MAC after this is a ghost of the decoy and is forgotten; one from before is a real machine.
    enabled_at TEXT    CHECK (enabled_at IS NULL OR length(enabled_at) = 24),
    created_at TEXT    NOT NULL CHECK (created_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z')
) STRICT;

CREATE TABLE "hp_config" (
    key        TEXT NOT NULL PRIMARY KEY CHECK (key IN ('applied', 'tail', 'https')),
    value      TEXT NOT NULL CHECK (json_valid(value)),
    updated_at TEXT NOT NULL CHECK (updated_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    updated_by TEXT NOT NULL CHECK (length(updated_by) > 0)
) STRICT;

CREATE TABLE "hp_hits" (
    id             TEXT    NOT NULL PRIMARY KEY CHECK (length(id) BETWEEN 1 AND 96),
    ts             TEXT    NOT NULL CHECK (ts GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    kind           TEXT    NOT NULL CHECK (kind IN ('service', 'token', 'scan')),
    service        TEXT    CHECK (service IS NULL OR service IN ('smb', 'rdp', 'ssh', 'mssql', 'http', 'https', 'ftp', 'telnet', 'mysql',
                                                             'mongodb', 'redis', 'vnc', 'git', 'httpproxy', 'tcpbanner', 'tftp', 'ntp', 'sip')),
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
    conn_key       TEXT    UNIQUE CHECK (conn_key IS NULL OR length(conn_key) = 64),
    conn_count     INTEGER NOT NULL DEFAULT 1 CHECK (conn_count >= 1),
    handshake      INTEGER NOT NULL DEFAULT 1 CHECK (handshake IN (0, 1))
) STRICT;

CREATE UNIQUE INDEX hp_tokens_name_ux ON hp_tokens (type, lower(name));

CREATE INDEX hp_hits_ts_ix ON hp_hits (ts DESC);

CREATE INDEX hp_hits_src_ix ON hp_hits (src_ip);

CREATE INDEX hp_hits_token_ix ON hp_hits (token_id) WHERE token_id IS NOT NULL;
