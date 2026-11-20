-- +goose Up
-- The whole schema of the sensor-active module. It is edited in place until the first public release; docs/SCHEMA.sql
-- shows the schema of every module together. Forward-only: there is no Down section.

-- Where the sweep of the confirmed ranges stands (one row): the last address of the last batch finished, or
-- NULL when no pass is in progress. A window that cuts a pass is continued from here the next day; when the
-- pass reaches the end of the ranges the cursor is cleared and the next pass starts from the first address.
CREATE TABLE sa_sweep (
    id         INTEGER NOT NULL PRIMARY KEY CHECK (id = 1),
    cursor     TEXT    CHECK (cursor IS NULL OR length(cursor) BETWEEN 7 AND 15),
    updated_at TEXT    NOT NULL CHECK (updated_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z')
);

-- Devices waiting for their scan inside a window; kept here so a restart does not lose them.
CREATE TABLE sa_queue (
    asset_id  TEXT    NOT NULL PRIMARY KEY CHECK (length(asset_id) BETWEEN 1 AND 96),
    queued_at TEXT    NOT NULL CHECK (queued_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    reason    TEXT    NOT NULL CHECK (length(reason) BETWEEN 1 AND 64),
    attempts  INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0)
);

CREATE TABLE sa_first_pass (
    id         INTEGER NOT NULL PRIMARY KEY CHECK (id = 1),
    started_at TEXT    NOT NULL CHECK (started_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z')
);

CREATE TABLE sa_snmp (
    id             TEXT    NOT NULL PRIMARY KEY CHECK (length(id) BETWEEN 1 AND 96),
    name           TEXT    NOT NULL CHECK (length(name) BETWEEN 1 AND 64),
    version        TEXT    NOT NULL CHECK (version IN ('v2c', 'v3')),
    username       TEXT    CHECK (username IS NULL OR length(username) BETWEEN 1 AND 64),
    auth           TEXT    CHECK (auth IS NULL OR auth IN ('sha', 'sha256')),
    priv           TEXT    CHECK (priv IS NULL OR priv = 'aes128'),
    secret_id      TEXT    NOT NULL CHECK (length(secret_id) BETWEEN 1 AND 96),
    secret_last4   TEXT    NOT NULL DEFAULT '' CHECK (length(secret_last4) <= 4),
    priv_secret_id TEXT    CHECK (priv_secret_id IS NULL OR length(priv_secret_id) BETWEEN 1 AND 96),
    priv_last4     TEXT    NOT NULL DEFAULT '' CHECK (length(priv_last4) <= 4),
    scope          TEXT    NOT NULL CHECK (json_valid(scope) AND json_type(scope) = 'array' AND json_array_length(scope) BETWEEN 1 AND 16 AND length(scope) <= 1000),
    created_at     TEXT    NOT NULL CHECK (created_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    updated_at     TEXT    NOT NULL CHECK (updated_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    last_answer_at TEXT    CHECK (last_answer_at IS NULL OR last_answer_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    answered       INTEGER NOT NULL DEFAULT 0 CHECK (answered >= 0), port INTEGER CHECK (port IS NULL OR port BETWEEN 1 AND 65535),
    CHECK ((version = 'v2c' AND username IS NULL AND auth IS NULL AND priv IS NULL AND priv_secret_id IS NULL)
        OR (version = 'v3' AND username IS NOT NULL AND auth IS NOT NULL AND (priv IS NULL) = (priv_secret_id IS NULL)))
);

CREATE TABLE "sa_job" (
    id          TEXT    NOT NULL PRIMARY KEY CHECK (length(id) BETWEEN 1 AND 96),
    kind        TEXT    NOT NULL CHECK (kind IN ('sweep', 'device', 'snmp', 'external')),
    reason      TEXT    CHECK (reason IS NULL OR length(reason) <= 64),
    started_at  TEXT    NOT NULL CHECK (started_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    finished_at TEXT    CHECK (finished_at IS NULL OR finished_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    status      TEXT    NOT NULL CHECK (status IN ('running', 'done', 'stopped', 'failed')),
    targets     INTEGER NOT NULL DEFAULT 0 CHECK (targets >= 0),
    new_devices INTEGER NOT NULL DEFAULT 0 CHECK (new_devices >= 0),
    error       TEXT    CHECK (error IS NULL OR length(error) <= 1000)
, asset_id TEXT CHECK (asset_id IS NULL OR length(asset_id) BETWEEN 1 AND 96), found TEXT CHECK (found IS NULL OR (json_valid(found) AND json_type(found) = 'object' AND length(found) <= 8000)));

-- Three new LAN shapes. 'extra_ports' follows every normal or versions scan of a device (the
-- surface list and the reviewed admin ports, nmapargv.ExtraPorts); 'all_ports' is the weekly port discovery over every TCP port of
-- each LAN device that is not fragile (its job is of kind 'device', reason 'all_ports'); 'port_versions' is its -sV follow-up on
-- at most 20 of the ports it found. For them sa_probe is rebuilt with the same columns and ids the way 0006 did it, the
-- AUTOINCREMENT counter going on from the old one. sa_all_ports keeps, per device: when its last weekly run was made or found the
-- device not eligible (fragile, kind unknown, never, the box: looked at again a week later; NULL: never) or answering on every
-- port; the open ports and software a normal scan found (the follow-up does not read them again; the weekly run adds its products
-- to that software); the products the follow-ups read, by port; when each port was last read; and the open ports the last done weekly run found outside
-- nmapargv.ExtraPorts with that run's time, so a normal scan keeps the ones it does not find itself until the next weekly run, 14
-- days at most. Rows of devices the inventory no longer has are removed by the weekly round. Forward-only (DATA_MODEL 6, rule 1).
CREATE TABLE sa_all_ports (
    asset_id     TEXT NOT NULL PRIMARY KEY CHECK (length(asset_id) BETWEEN 1 AND 96),
    last_at      TEXT CHECK (last_at IS NULL OR last_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    -- retry: one failure, tried again in the next window (still due); the others make the device due a week after last_at
    outcome      TEXT CHECK (outcome IS NULL OR outcome IN ('done', 'not_eligible', 'answers_everywhere', 'retry', 'failed')),
    -- observe.Service[] of the open ports outside nmapargv.ExtraPorts that the last done weekly run found, at extra_at
    extra        TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(extra) AND json_type(extra) = 'array' AND length(extra) <= 262144),
    -- [{port, software}] the weekly follow-ups read, kept by port and product
    extra_sw     TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(extra_sw) AND json_type(extra_sw) = 'array' AND length(extra_sw) <= 262144),
    extra_at     TEXT CHECK (extra_at IS NULL OR extra_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    -- {"port": time} when the follow-up last read each open port with -sV
    versioned    TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(versioned) AND json_type(versioned) = 'object' AND length(versioned) <= 65536),
    -- the TCP ports and the software the last normal or versions scan found (NULL software: none recorded by an older scan)
    normal_ports TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(normal_ports) AND json_type(normal_ports) = 'array' AND length(normal_ports) <= 16384),
    normal_sw    TEXT CHECK (normal_sw IS NULL OR (json_valid(normal_sw) AND json_type(normal_sw) = 'array' AND length(normal_sw) <= 262144))
);

CREATE TABLE "sa_probe" (
    id           INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    time         TEXT    NOT NULL CHECK (time GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    job_id       TEXT    NOT NULL REFERENCES sa_job (id),
    shape        TEXT    NOT NULL CHECK (shape IN ('sweep', 'normal', 'gentle', 'versions', 'gentle_titles', 'snmp', 'external', 'external_full', 'external_disruptive', 'all_ports', 'extra_ports', 'port_versions')),
    rate         INTEGER NOT NULL CHECK (rate BETWEEN 1 AND 1000),
    hosts        INTEGER NOT NULL CHECK (hosts BETWEEN 1 AND 64),
    flags        TEXT    NOT NULL CHECK (length(flags) BETWEEN 1 AND 16384),
    targets      TEXT    NOT NULL CHECK (length(targets) BETWEEN 7 AND 1100),
    result       TEXT    NOT NULL CHECK (length(result) <= 200)
);

CREATE TABLE sa_snmp_answer (
    credential_id TEXT NOT NULL REFERENCES sa_snmp (id) ON DELETE CASCADE,
    asset_id      TEXT NOT NULL CHECK (length(asset_id) BETWEEN 1 AND 96),
    ip            TEXT NOT NULL CHECK (length(ip) BETWEEN 7 AND 15),
    answered_at   TEXT NOT NULL CHECK (answered_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'), sys_descr TEXT CHECK (sys_descr IS NULL OR length(sys_descr) BETWEEN 1 AND 200), sys_object_id TEXT CHECK (sys_object_id IS NULL OR length(sys_object_id) BETWEEN 1 AND 200),
    PRIMARY KEY (credential_id, asset_id)
);

-- SNMP is set up per device. sa_snmp_device holds one device's SNMP settings: its read address (the one
-- address its reads and its secret go to: the device's IP by default, or its management address, such as a FortiGate's global VDOM
-- interface), the version, the v3 user and algorithms, the UDP port (NULL = 161) and the ids of its secrets in core_secret (never
-- the secrets), with the state of its last read: when it was sent, what came back, and what the device said (answer: the JSON of
-- the values the worker read, cleaned and bounded; untrusted text, only ever parsed through the fixed layouts of snmpmap.go).
-- asset_id is the inventory's device id (no reference across modules: the rows go with inventory.asset.deleted and move with
-- inventory.asset.merged). read_from_default is 1 when the read address was the device's own IP when saved: if the device then moves,
-- nothing is sent until a person sets the address again.
-- sa_snmp_notice keeps what the box changed by itself (the move of the old SNMP credentials to the devices they covered) until a
-- person dismisses it. sa_snmp and sa_snmp_answer stay until a later release drops them: sensor-active empties them once, in Go,
-- because the secrets are opened and sealed again through core/secrets (snmp_move.go). Forward-only (DATA_MODEL 6, rule 1).
CREATE TABLE sa_snmp_device (
    asset_id          TEXT    NOT NULL PRIMARY KEY CHECK (length(asset_id) BETWEEN 1 AND 96),
    read_from         TEXT    NOT NULL CHECK (length(read_from) BETWEEN 7 AND 15),
    read_from_default INTEGER NOT NULL CHECK (read_from_default IN (0, 1)),
    version           TEXT    NOT NULL CHECK (version IN ('v2c', 'v3')),
    username          TEXT    CHECK (username IS NULL OR length(username) BETWEEN 1 AND 64),
    auth              TEXT    CHECK (auth IS NULL OR auth IN ('sha', 'sha256')),
    priv              TEXT    CHECK (priv IS NULL OR priv = 'aes128'),
    secret_id         TEXT    NOT NULL CHECK (length(secret_id) BETWEEN 1 AND 96),
    secret_last4      TEXT    NOT NULL DEFAULT '' CHECK (length(secret_last4) <= 4),
    priv_secret_id    TEXT    CHECK (priv_secret_id IS NULL OR length(priv_secret_id) BETWEEN 1 AND 96),
    priv_last4        TEXT    NOT NULL DEFAULT '' CHECK (length(priv_last4) <= 4),
    port              INTEGER CHECK (port IS NULL OR port BETWEEN 1 AND 65535),
    created_at        TEXT    NOT NULL CHECK (created_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    updated_at        TEXT    NOT NULL CHECK (updated_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    last_checked_at   TEXT    CHECK (last_checked_at IS NULL OR last_checked_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    last_status       TEXT    CHECK (last_status IS NULL OR last_status IN ('ok', 'no_answer', 'auth_failed', 'unknown_user', 'error')),
    last_answer_at    TEXT    CHECK (last_answer_at IS NULL OR last_answer_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    answer            TEXT    CHECK (answer IS NULL OR (json_valid(answer) AND length(answer) <= 6000)),
    CHECK ((version = 'v2c' AND username IS NULL AND auth IS NULL AND priv IS NULL AND priv_secret_id IS NULL)
        OR (version = 'v3' AND username IS NOT NULL AND auth IS NOT NULL AND (priv IS NULL) = (priv_secret_id IS NULL)))
);

CREATE TABLE sa_snmp_notice (
    id   INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    at   TEXT    NOT NULL CHECK (at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    text TEXT    NOT NULL CHECK (length(text) BETWEEN 1 AND 2000)
);

CREATE UNIQUE INDEX sa_snmp_name_ux ON sa_snmp (name COLLATE NOCASE);

CREATE INDEX sa_job_started_ix ON sa_job (kind, started_at);

CREATE INDEX sa_probe_time_ix ON sa_probe (time);

CREATE INDEX sa_probe_job_ix ON sa_probe (job_id);

CREATE INDEX sa_snmp_answer_asset_ix ON sa_snmp_answer (asset_id);

CREATE INDEX sa_job_asset_ix ON sa_job (asset_id, started_at) WHERE asset_id IS NOT NULL;
