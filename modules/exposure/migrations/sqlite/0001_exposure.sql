-- +goose Up
-- The whole schema of the exposure module. It is edited in place until the first public release; docs/SCHEMA.sql
-- shows the schema of every module together. Forward-only: there is no Down section.

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
    last_scan_at  TEXT CHECK (last_scan_at IS NULL OR last_scan_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'), commitment_version TEXT CHECK (commitment_version IS NULL OR (length(commitment_version) BETWEEN 1 AND 40 AND commitment_by IS NOT NULL)), commitment_sentence TEXT CHECK ((commitment_version IS NULL) = (commitment_sentence IS NULL) AND (commitment_sentence IS NULL OR length(commitment_sentence) BETWEEN 1 AND 1000)), commitment_user_id TEXT CHECK (commitment_user_id IS NULL OR (length(commitment_user_id) BETWEEN 1 AND 96 AND commitment_version IS NOT NULL)), commitment_method TEXT CHECK ((commitment_user_id IS NULL) = (commitment_method IS NULL) AND (commitment_method IS NULL OR commitment_method IN ('app', 'email', 'sso'))), terms_version TEXT, terms_by TEXT, terms_at TEXT, terms_text TEXT, terms_user_id TEXT, terms_method TEXT, terms_disruptive INTEGER NOT NULL DEFAULT 0 CHECK (terms_disruptive IN (0, 1)), typed INTEGER NOT NULL DEFAULT 0 CHECK (typed IN (0, 1) AND (typed = 0 OR kind = 'ip')), ip_token TEXT CHECK (ip_token IS NULL OR (typed = 1 AND length(ip_token) = 16)), proof_method TEXT CHECK (proof_method IS NULL OR (typed = 1 AND proof_method IN ('ip_file', 'ip_ptr'))), scan_every TEXT NOT NULL DEFAULT 'weekly' CHECK (scan_every IN ('off', 'daily', 'weekly', 'monthly')), sched_skip TEXT CHECK (sched_skip IS NULL OR length(sched_skip) BETWEEN 1 AND 1000), sched_skip_at TEXT CHECK ((sched_skip_at IS NULL) = (sched_skip IS NULL) AND (sched_skip_at IS NULL OR sched_skip_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z')), sched_retry_at TEXT CHECK (sched_retry_at IS NULL OR (sched_skip IS NOT NULL AND sched_retry_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z')),
    CHECK ((commitment_by IS NULL) = (commitment_at IS NULL))
);

CREATE TABLE exp_snapshot (
    id           TEXT NOT NULL PRIMARY KEY CHECK (length(id) BETWEEN 1 AND 96),
    target_id    TEXT NOT NULL REFERENCES exp_target (id) ON DELETE CASCADE,
    date         TEXT NOT NULL CHECK (date GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]'),
    scanned_at   TEXT NOT NULL CHECK (scanned_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    hosts        TEXT NOT NULL CHECK (json_valid(hosts) AND json_type(hosts) = 'array'),
    ports        TEXT NOT NULL CHECK (json_valid(ports) AND json_type(ports) = 'array'),
    admin_panels TEXT NOT NULL CHECK (json_valid(admin_panels) AND json_type(admin_panels) = 'array'),
    certs        TEXT NOT NULL CHECK (json_valid(certs) AND json_type(certs) = 'array'),
    counts       TEXT NOT NULL CHECK (json_valid(counts) AND json_type(counts) = 'object'), services TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(services) AND json_type(services) = 'array'), checks TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(checks) AND json_type(checks) = 'array'), not_checked TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(not_checked) AND json_type(not_checked) = 'array'), web_findings TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(web_findings) AND json_type(web_findings) = 'array'), greenbone TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(greenbone) AND json_type(greenbone) = 'array'), scripts TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(scripts) AND json_type(scripts) = 'array'), greenbone_run TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(greenbone_run) AND json_type(greenbone_run) = 'object'), started_at TEXT CHECK (started_at IS NULL OR started_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'), finished_at TEXT CHECK (finished_at IS NULL OR finished_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    UNIQUE (target_id, date)
);

-- The attempts people made to verify something, for the limit of 10 per hour (INV-5). Kept 24 hours.
CREATE TABLE exp_attempt (
    id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    ts TEXT    NOT NULL CHECK (ts GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z')
);

CREATE TABLE exp_setting (
    id               INTEGER NOT NULL PRIMARY KEY CHECK (id = 1),
    last_run_at      TEXT CHECK (last_run_at IS NULL OR last_run_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    last_run_ok      INTEGER CHECK (last_run_ok IS NULL OR last_run_ok IN (0, 1)),
    last_run_message TEXT CHECK (last_run_message IS NULL OR length(last_run_message) <= 1000),
    last_deep_at     TEXT CHECK (last_deep_at IS NULL OR last_deep_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    last_full_ok_at  TEXT CHECK (last_full_ok_at IS NULL OR last_full_ok_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'), greenbone INTEGER NOT NULL DEFAULT 0 CHECK (greenbone IN (0, 1)), greenbone_by TEXT, greenbone_at TEXT, greenbone_sync_at TEXT, greenbone_sync_ok INTEGER CHECK (greenbone_sync_ok IN (0, 1)), greenbone_sync_note TEXT,
    CHECK ((last_run_at IS NULL) = (last_run_ok IS NULL) AND (last_run_at IS NULL) = (last_run_message IS NULL))
);

-- The Ignored list (INV-14): public IPs a person removed and chose not to add again, for example the address of a
-- security gateway, a VPN exit or a mobile backup line that the box sometimes uses but that is not the company's.
-- The list only blocks: detection never adds these addresses and nothing scans them. Restoring one deletes its row, which
-- lets detection add the address again; it never creates or approves a target. Forward-only (DATA_MODEL 6, rule 1).
CREATE TABLE exp_ignored (
    value      TEXT NOT NULL PRIMARY KEY CHECK (length(value) BETWEEN 7 AND 15 AND value GLOB '[0-9]*.[0-9]*.[0-9]*.[0-9]*' AND value NOT GLOB '*[^0-9.]*'),
    ignored_by TEXT NOT NULL CHECK (length(ignored_by) BETWEEN 1 AND 320),
    ignored_at TEXT NOT NULL CHECK (ignored_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z')
);

-- What the Internet sees (INV-21): the last answer of Shodan InternetDB about one of the box's own public IPs, asked only
-- when an administrator clicks. One row per target, replaced by the next check, gone with its target; the audit log keeps every
-- request that was sent. answer is {ports, hostnames, cpes, tags, vulns}, already limited and checked when it was read (INV-10):
-- it is Shodan's claim, never a finding of Vedette. Forward-only (DATA_MODEL 6, rule 1).
CREATE TABLE exp_outside (
    target_id  TEXT NOT NULL PRIMARY KEY REFERENCES exp_target (id) ON DELETE CASCADE,
    ip         TEXT NOT NULL CHECK (length(ip) BETWEEN 7 AND 15 AND ip NOT GLOB '*[^0-9.]*'),
    checked_at TEXT NOT NULL CHECK (checked_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    checked_by TEXT NOT NULL CHECK (length(checked_by) BETWEEN 1 AND 320),
    found      INTEGER NOT NULL CHECK (found IN (0, 1)),
    answer     TEXT NOT NULL CHECK (json_valid(answer) AND json_type(answer) = 'object')
);

-- #861 (INV-30): the newest external scan in which each engine step actually ran (nuclei's templates, ZAP's passive web scan,
-- OpenVAS), with how it ended and a short text: Settings › Scanning's nuclei, zap and openvas cards read their last run here. A run
-- that skipped the step leaves the row as it was; a scan of the same target later the same day replaces the snapshot, never this row.
-- Deleting (or ignoring) the target deletes its rows. Forward-only (DATA_MODEL 6, rule 1).
CREATE TABLE exp_engine_run (
    engine  TEXT NOT NULL PRIMARY KEY CHECK (engine IN ('nuclei', 'zap', 'openvas')),
    run_id  TEXT NOT NULL CHECK (length(run_id) BETWEEN 1 AND 96),
    target  TEXT NOT NULL CHECK (length(target) BETWEEN 1 AND 253),
    at      TEXT NOT NULL CHECK (at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    outcome TEXT NOT NULL CHECK (outcome IN ('ok', 'partial', 'failed', 'stopped')),
    text    TEXT NOT NULL CHECK (length(text) BETWEEN 1 AND 300)
);

CREATE INDEX exp_attempt_ts_idx ON exp_attempt (ts);

INSERT INTO exp_setting (id) VALUES (1);
