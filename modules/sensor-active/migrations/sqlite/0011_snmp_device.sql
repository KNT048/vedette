-- +goose Up
-- D-607 (kien 2026-11-17, J2): SNMP is set up per device. sa_snmp_device holds one device's SNMP settings: its read address (the one
-- address its reads and its secret go to: the device's IP by default, or its management address, such as a FortiGate's global VDOM
-- interface), the version, the v3 user and algorithms, the UDP port (NULL = 161) and the ids of its secrets in core_secret (never
-- the secrets), with the state of its last read: when it was sent, what came back, and what the device said (answer: the JSON of
-- the values the worker read, cleaned and bounded; untrusted text, only ever parsed through the fixed layouts of snmpmap.go).
-- asset_id is the inventory's device id (no reference across modules: the rows go with inventory.asset.deleted and move with
-- inventory.asset.merged). read_from_default is 1 when the read address was the device's own IP when saved: if the device then moves,
-- nothing is sent until a person sets the address again.
-- sa_snmp_notice keeps what the box changed by itself (the move of the credentials of before D-607 to the devices they covered) until a
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
