-- +goose Up
-- The whole schema of the sensor-active module. It is edited in place until the first public release; docs/SCHEMA.sql
-- shows the schema of every module together. Forward-only: there is no Down section.

-- Every piece of work of this module is a run of core/run (core_run with its steps, items and log): a LAN sweep (kind lan_sweep:
-- one run per pass, across windows, one step per range whose done count is its cursor), a device check (device_check: a device
-- waiting for its turn in the scan window is a waiting run), an SNMP read (snmp_read), the weekly scan of every port of a device
-- (all_ports) and the service scan of a public address for exposure (service_scan). The tables below keep what is this module's
-- own: the probes each run sent, the weekly all-ports state and each device's SNMP settings.

-- Three new LAN shapes. 'extra_ports' follows every normal or versions scan of a device (the
-- surface list and the reviewed admin ports, nmapargv.ExtraPorts); 'all_ports' is the weekly port discovery over every TCP port of
-- each LAN device that is not fragile (its job is of kind 'device', reason 'all_ports'); 'port_versions' is its -sV follow-up on
-- at most 20 of the ports it found. For them sa_probe is rebuilt with the same columns and ids the way 0006 did it, the
-- AUTOINCREMENT counter going on from the old one. sa_all_ports keeps, per device, the schedule of its weekly run: when it was last
-- made or found the device not eligible (fragile, kind unknown, never, the box: looked at again a week later; NULL: never) or
-- answering on every port. What the scans found is in the inventory (the weekly run and the normal scan each replace only the ports
-- they looked at; when each port was last read with -sV is inv_service.read_at), not here. Rows of devices the inventory no longer has are removed by the weekly round. Forward-only (DATA_MODEL 6, rule 1).
CREATE TABLE sa_all_ports (
    asset_id     TEXT NOT NULL PRIMARY KEY CHECK (length(asset_id) BETWEEN 1 AND 96),
    last_at      TEXT CHECK (last_at IS NULL OR last_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    -- retry: one failure, tried again in the next window (still due); the others make the device due a week after last_at
    outcome      TEXT CHECK (outcome IS NULL OR outcome IN ('done', 'not_eligible', 'answers_everywhere', 'retry', 'failed'))
);

-- One row per nmap or SNMP job sent (INV-9: no packet without a log line), kept ProbeRetention. run_id is the run it was sent for;
-- NULL once that run is deleted (runs are kept longer than probes, so only by a purge).
CREATE TABLE "sa_probe" (
    id           INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    time         TEXT    NOT NULL CHECK (time GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    run_id       TEXT    REFERENCES core_run (id) ON DELETE SET NULL,
    shape        TEXT    NOT NULL CHECK (shape IN ('sweep', 'normal', 'gentle', 'versions', 'gentle_titles', 'snmp', 'external', 'external_full', 'external_disruptive', 'all_ports', 'extra_ports', 'port_versions')),
    rate         INTEGER NOT NULL CHECK (rate BETWEEN 1 AND 1000),
    hosts        INTEGER NOT NULL CHECK (hosts BETWEEN 1 AND 64),
    flags        TEXT    NOT NULL CHECK (length(flags) BETWEEN 1 AND 16384),
    targets      TEXT    NOT NULL CHECK (length(targets) BETWEEN 7 AND 1100),
    result       TEXT    NOT NULL CHECK (length(result) <= 200)
);

-- SNMP is set up per device. sa_snmp_device holds one device's SNMP settings: its read address (the one
-- address its reads and its secret go to: the device's IP by default, or its management address, such as a FortiGate's global VDOM
-- interface), the version, the v3 user and algorithms, the UDP port (NULL = 161) and the ids of its secrets in core_secret (never
-- the secrets), with the state of its last read: when it was sent, what came back, and what the device said (answer: the JSON of
-- the values the worker read, cleaned and bounded; untrusted text, only ever parsed through the fixed layouts of snmpmap.go).
-- asset_id is the inventory's device (a deleted device takes its row; the device lifecycle drops its secrets first and moves the row
-- of a merged device). read_from_default is 1 when the read address was the device's own IP when saved: if the device then moves,
-- nothing is sent until a person sets the address again.
CREATE TABLE sa_snmp_device (
    asset_id          TEXT    NOT NULL PRIMARY KEY REFERENCES inv_asset (id) ON DELETE CASCADE CHECK (length(asset_id) BETWEEN 1 AND 96),
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

-- What the box changed in SNMP settings by itself (a merge of two devices that both had SNMP set up: which was kept), until a
-- person dismisses it.
CREATE TABLE sa_snmp_notice (
    id   INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    at   TEXT    NOT NULL CHECK (at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    text TEXT    NOT NULL CHECK (length(text) BETWEEN 1 AND 2000)
);

CREATE INDEX sa_probe_time_ix ON sa_probe (time);

CREATE INDEX sa_probe_run_ix ON sa_probe (run_id);
