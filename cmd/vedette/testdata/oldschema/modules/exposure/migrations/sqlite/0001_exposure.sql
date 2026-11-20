-- +goose Up
-- External exposure (docs/DATA_MODEL.md 4.5, modules/exposure/CONTRACT.md). Forward-only (DATA_MODEL 6, rule 1).

-- A domain (proved by a DNS TXT record) or a public IP (found by the box itself, never typed in: INV-2).
-- For an IP, verified_at is the last time the box saw it and the 30-day validity is derived from it (INV-4),
-- so there is no expires_at column to drift. The commitment (D-26) is two columns of the same row.
CREATE TABLE exp_target (
    id            TEXT NOT NULL PRIMARY KEY CHECK (length(id) BETWEEN 1 AND 96),
    kind          TEXT NOT NULL CHECK (kind IN ('domain', 'ip')),
    value         TEXT NOT NULL UNIQUE CHECK (length(value) BETWEEN 1 AND 253),
    method        TEXT CHECK (method IS NULL OR (kind = 'domain' AND method = 'dns_txt') OR (kind = 'ip' AND method = 'box_egress')),
    -- domain: the value in the TXT record vedette-verify=<token> (public in DNS); IP: ''
    token         TEXT NOT NULL CHECK ((kind = 'domain' AND length(token) = 16) OR (kind = 'ip' AND token = '')),
    verified_at   TEXT CHECK (verified_at IS NULL OR verified_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    -- {at, ok, message}
    last_check    TEXT CHECK (last_check IS NULL OR (json_valid(last_check) AND json_type(last_check) = 'object')),
    commitment_by TEXT CHECK (commitment_by IS NULL OR length(commitment_by) BETWEEN 1 AND 320),
    commitment_at TEXT CHECK (commitment_at IS NULL OR commitment_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    created_at    TEXT NOT NULL CHECK (created_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    last_scan_at  TEXT CHECK (last_scan_at IS NULL OR last_scan_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    CHECK ((commitment_by IS NULL) = (commitment_at IS NULL))
);

-- One result per target and day (INV-8). Gone with its target (INV-7); the audit log is not.
CREATE TABLE exp_snapshot (
    id           TEXT NOT NULL PRIMARY KEY CHECK (length(id) BETWEEN 1 AND 96),
    target_id    TEXT NOT NULL REFERENCES exp_target (id) ON DELETE CASCADE,
    date         TEXT NOT NULL CHECK (date GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]'),
    scanned_at   TEXT NOT NULL CHECK (scanned_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    hosts        TEXT NOT NULL CHECK (json_valid(hosts) AND json_type(hosts) = 'array'),
    ports        TEXT NOT NULL CHECK (json_valid(ports) AND json_type(ports) = 'array'),
    admin_panels TEXT NOT NULL CHECK (json_valid(admin_panels) AND json_type(admin_panels) = 'array'),
    certs        TEXT NOT NULL CHECK (json_valid(certs) AND json_type(certs) = 'array'),
    counts       TEXT NOT NULL CHECK (json_valid(counts) AND json_type(counts) = 'object'),
    UNIQUE (target_id, date)
);

-- The attempts people made to verify something, for the limit of 10 per hour (INV-5). Kept 24 hours.
CREATE TABLE exp_attempt (
    id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    ts TEXT    NOT NULL CHECK (ts GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z')
);

CREATE INDEX exp_attempt_ts_idx ON exp_attempt (ts);

-- The auto-detect settings of the box (INV-11): one row, with the defaults of kien's decision of 2026-11-09
-- (on, every 60 minutes, 1 to 1440) and the follow-up of kien. last_run_* is the last detection, automatic or by a click;
-- last_deep_at is the last full check (several rounds), so that a short interval only does a full check once an hour.
-- last_full_ok_at is the last full check that got an answer (the services agreed): an IP not seen by it, and not seen since,
-- is shown as paused (INV-13). A failed check moves last_deep_at but never this column.
CREATE TABLE exp_setting (
    id               INTEGER NOT NULL PRIMARY KEY CHECK (id = 1),
    auto             INTEGER NOT NULL DEFAULT 1 CHECK (auto IN (0, 1)),
    interval_min     INTEGER NOT NULL DEFAULT 60 CHECK (interval_min BETWEEN 1 AND 1440),
    last_run_at      TEXT CHECK (last_run_at IS NULL OR last_run_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    last_run_ok      INTEGER CHECK (last_run_ok IS NULL OR last_run_ok IN (0, 1)),
    last_run_message TEXT CHECK (last_run_message IS NULL OR length(last_run_message) <= 1000),
    last_deep_at     TEXT CHECK (last_deep_at IS NULL OR last_deep_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    last_full_ok_at  TEXT CHECK (last_full_ok_at IS NULL OR last_full_ok_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    CHECK ((last_run_at IS NULL) = (last_run_ok IS NULL) AND (last_run_at IS NULL) = (last_run_message IS NULL))
);

INSERT INTO exp_setting (id) VALUES (1);
