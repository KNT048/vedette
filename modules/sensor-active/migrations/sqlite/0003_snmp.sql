-- +goose Up
-- D-512: SNMP reads. (1) sa_snmp holds the SNMP credentials an administrator saved: their secrets are in core_secret (a v2c
-- community or a v3 authentication password in secret_id, a v3 privacy password in priv_secret_id), never here; the last 4
-- characters are kept for the GUI ("" when the secret is shorter than 8). scope is a JSON array of IPv4 addresses and CIDR ranges
-- the credential may be sent to, [] for every device in the scan scope. (2) A run of SNMP reads is a job of kind 'snmp' and each
-- job a probe row of shape 'snmp', so the probe log answers "which device got which credential when" as it does for nmap. SQLite
-- cannot change a CHECK: sa_job and sa_probe are rebuilt with the same columns and ids. sa_probe refers to sa_job, so the new
-- sa_probe is made against the new sa_job before the old tables go, and the renames carry the reference (SQLite 3.26+).
-- Forward-only (DATA_MODEL 6, rule 1).
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
    scope          TEXT    NOT NULL DEFAULT '[]' CHECK (json_valid(scope) AND json_type(scope) = 'array' AND length(scope) <= 1000),
    created_at     TEXT    NOT NULL CHECK (created_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    updated_at     TEXT    NOT NULL CHECK (updated_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    last_answer_at TEXT    CHECK (last_answer_at IS NULL OR last_answer_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    answered       INTEGER NOT NULL DEFAULT 0 CHECK (answered >= 0),
    CHECK ((version = 'v2c' AND username IS NULL AND auth IS NULL AND priv IS NULL AND priv_secret_id IS NULL)
        OR (version = 'v3' AND username IS NOT NULL AND auth IS NOT NULL AND (priv IS NULL) = (priv_secret_id IS NULL)))
);
CREATE UNIQUE INDEX sa_snmp_name_ux ON sa_snmp (name COLLATE NOCASE);

CREATE TABLE sa_job_new (
    id          TEXT    NOT NULL PRIMARY KEY CHECK (length(id) BETWEEN 1 AND 96),
    kind        TEXT    NOT NULL CHECK (kind IN ('sweep', 'device', 'snmp')),
    reason      TEXT    CHECK (reason IS NULL OR length(reason) <= 64),
    started_at  TEXT    NOT NULL CHECK (started_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    finished_at TEXT    CHECK (finished_at IS NULL OR finished_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    status      TEXT    NOT NULL CHECK (status IN ('running', 'done', 'stopped', 'failed')),
    targets     INTEGER NOT NULL DEFAULT 0 CHECK (targets >= 0),
    new_devices INTEGER NOT NULL DEFAULT 0 CHECK (new_devices >= 0),
    error       TEXT    CHECK (error IS NULL OR length(error) <= 1000)
);
INSERT INTO sa_job_new (id, kind, reason, started_at, finished_at, status, targets, new_devices, error)
    SELECT id, kind, reason, started_at, finished_at, status, targets, new_devices, error FROM sa_job;

CREATE TABLE sa_probe_new (
    id           INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    time         TEXT    NOT NULL CHECK (time GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    job_id       TEXT    NOT NULL REFERENCES sa_job_new (id),
    shape        TEXT    NOT NULL CHECK (shape IN ('sweep', 'normal', 'gentle', 'versions', 'snmp')),
    rate         INTEGER NOT NULL CHECK (rate BETWEEN 1 AND 1000),
    hosts        INTEGER NOT NULL CHECK (hosts BETWEEN 1 AND 64),
    flags        TEXT    NOT NULL CHECK (length(flags) BETWEEN 1 AND 300),
    targets      TEXT    NOT NULL CHECK (length(targets) BETWEEN 7 AND 1100),
    result       TEXT    NOT NULL CHECK (length(result) <= 200)
);
INSERT INTO sa_probe_new (id, time, job_id, shape, rate, hosts, flags, targets, result)
    SELECT id, time, job_id, shape, rate, hosts, flags, targets, result FROM sa_probe;

DROP TABLE sa_probe;
DROP TABLE sa_job;
ALTER TABLE sa_job_new RENAME TO sa_job;
ALTER TABLE sa_probe_new RENAME TO sa_probe;
CREATE INDEX sa_job_started_ix ON sa_job (kind, started_at);
CREATE INDEX sa_probe_time_ix ON sa_probe (time);
CREATE INDEX sa_probe_job_ix ON sa_probe (job_id);
