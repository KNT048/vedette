-- +goose Up
-- The whole schema of the core module. It is edited in place until the first public release; docs/SCHEMA.sql
-- shows the schema of every module together. Forward-only: there is no Down section.

CREATE TABLE core_secret (
    id          TEXT    NOT NULL PRIMARY KEY CHECK (length(id) BETWEEN 1 AND 96),
    purpose     TEXT    NOT NULL CHECK (length(purpose) BETWEEN 1 AND 64),
    nonce       BLOB    NOT NULL CHECK (typeof(nonce) = 'blob' AND length(nonce) = 12),
    ciphertext  BLOB    NOT NULL CHECK (typeof(ciphertext) = 'blob' AND length(ciphertext) >= 16), -- includes the 16-byte GCM tag
    key_version INTEGER NOT NULL CHECK (key_version >= 1),
    last4       TEXT    CHECK (last4 IS NULL OR length(last4) = 4),
    created_at  TEXT    NOT NULL CHECK (created_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    rotated_at  TEXT    CHECK (rotated_at IS NULL OR rotated_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z')
);

-- seq only orders rows (it is not part of the hash); AUTOINCREMENT so a pruned seq is never reused.
CREATE TABLE core_audit (
    seq       INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    id        TEXT    NOT NULL UNIQUE CHECK (length(id) BETWEEN 1 AND 96),
    prev_hash TEXT    NOT NULL CHECK (length(prev_hash) = 64),
    hash      TEXT    NOT NULL UNIQUE CHECK (length(hash) = 64),
    ts        TEXT    NOT NULL CHECK (ts GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    user      TEXT    NOT NULL CHECK (length(user) > 0),
    action    TEXT    NOT NULL CHECK (length(action) > 0),
    target    TEXT    NOT NULL CHECK (length(target) > 0),
    detail    TEXT
);

CREATE TABLE core_chain_anchor (
    chain            TEXT NOT NULL PRIMARY KEY CHECK (chain IN ('core_audit', 'ai_activity', 'resp_log')),
    last_pruned_id   TEXT NOT NULL,
    last_pruned_hash TEXT NOT NULL CHECK (length(last_pruned_hash) = 64),
    pruned_at        TEXT NOT NULL CHECK (pruned_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z')
);

-- One row per toggleable module. tier, depends and the rest come from MANIFEST.yaml in the code, not from here.
-- Rows are inserted at start-up from each manifest's default (ON CONFLICT DO NOTHING), never dropped:
-- turning a module off keeps its data and its row (INV-4).
CREATE TABLE core_module (
    id          TEXT    NOT NULL PRIMARY KEY CHECK (id GLOB '[a-z]*' AND length(id) BETWEEN 1 AND 32),
    enabled     BOOLEAN NOT NULL CHECK (enabled IN (0, 1)),
    enabled_at  TEXT    CHECK (enabled_at IS NULL OR enabled_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    disabled_at TEXT    CHECK (disabled_at IS NULL OR disabled_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    version     TEXT    NOT NULL CHECK (length(version) BETWEEN 1 AND 64)
);

-- One row per finished run of a scheduled job; the scheduler keeps the last 200 per (module, job).
-- A run is written when it ends, so there is no "running" status.
CREATE TABLE core_job_run (
    id          TEXT NOT NULL PRIMARY KEY CHECK (length(id) BETWEEN 1 AND 96),
    module      TEXT NOT NULL CHECK (length(module) BETWEEN 1 AND 32),
    job         TEXT NOT NULL CHECK (length(job) BETWEEN 1 AND 64),
    started_at  TEXT NOT NULL CHECK (started_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    finished_at TEXT NOT NULL CHECK (finished_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    status      TEXT NOT NULL CHECK (status IN ('ok', 'error', 'cancelled')),
    error       TEXT CHECK (error IS NULL OR length(error) <= 1000)
);

CREATE TABLE core_user (
    id            TEXT    NOT NULL PRIMARY KEY CHECK (length(id) BETWEEN 1 AND 96),
    name          TEXT    NOT NULL CHECK (length(name) BETWEEN 1 AND 200),
    email         TEXT    NOT NULL UNIQUE CHECK (email = lower(email) AND length(email) BETWEEN 3 AND 320),
    role          TEXT    NOT NULL CHECK (role IN ('viewer', 'operator', 'admin')),
    password_hash TEXT    NOT NULL CHECK (length(password_hash) BETWEEN 1 AND 512), -- argon2id PHC string
    cred_version  INTEGER NOT NULL DEFAULT 0 CHECK (cred_version >= 0), -- +1 on every real password change or reset (not on a rehash with new argon2 parameters)
    twofa_method  TEXT    CHECK (twofa_method IS NULL OR twofa_method IN ('app', 'email')),
    disabled      INTEGER NOT NULL DEFAULT 0 CHECK (disabled IN (0, 1)),
    created_at    TEXT    NOT NULL CHECK (created_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    last_login    TEXT    CHECK (last_login IS NULL OR last_login GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z')
, temp_password_expires_at TEXT CHECK (temp_password_expires_at IS NULL OR temp_password_expires_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'), sso_issuer TEXT CHECK (sso_issuer IS NULL OR (sso_issuer GLOB 'https://*' AND length(sso_issuer) <= 2048)), sso_subject TEXT CHECK (sso_subject IS NULL OR length(sso_subject) BETWEEN 1 AND 255));

-- The TOTP key is in core_secret (purpose core_user_totp). last_step is the time step of the last accepted
-- code: a code for a step at or before it is refused (replay protection). A confirmed=0 row is a key the
-- user has not proved yet; it expires 10 minutes after created_at.
CREATE TABLE core_user_totp (
    user_id   TEXT    NOT NULL PRIMARY KEY REFERENCES core_user (id) ON DELETE CASCADE,
    secret_id TEXT    NOT NULL REFERENCES core_secret (id),
    confirmed INTEGER NOT NULL DEFAULT 0 CHECK (confirmed IN (0, 1)),
    last_step INTEGER CHECK (last_step IS NULL OR last_step >= 0),
    created_at TEXT   NOT NULL CHECK (created_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z')
);

CREATE TABLE core_email_code (
    user_id    TEXT    NOT NULL PRIMARY KEY REFERENCES core_user (id) ON DELETE CASCADE,
    code_hash  TEXT    NOT NULL CHECK (length(code_hash) = 64), -- hex HMAC-SHA-256 of user id and the 6 digits
    expires_at TEXT    NOT NULL CHECK (expires_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    tries      INTEGER NOT NULL DEFAULT 0 CHECK (tries BETWEEN 0 AND 5),
    sent_at    TEXT    NOT NULL CHECK (sent_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z')
);

CREATE TABLE core_email_code_send (
    user_id TEXT NOT NULL REFERENCES core_user (id) ON DELETE CASCADE,
    sent_at TEXT NOT NULL CHECK (sent_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z')
, kind TEXT NOT NULL DEFAULT 'signin' CHECK (kind IN ('signin', 'stepup')));

CREATE TABLE core_session (
    id         TEXT NOT NULL PRIMARY KEY CHECK (length(id) BETWEEN 1 AND 96),
    user_id    TEXT NOT NULL REFERENCES core_user (id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL UNIQUE CHECK (length(token_hash) = 64), -- SHA-256 of the __Host-vedette_session cookie
    csrf_hash  TEXT NOT NULL CHECK (length(csrf_hash) = 64),         -- SHA-256 of the __Host-vedette_csrf cookie
    device     TEXT NOT NULL CHECK (length(device) <= 200),
    ip         TEXT NOT NULL CHECK (length(ip) BETWEEN 1 AND 64),
    started_at TEXT NOT NULL CHECK (started_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    last_seen  TEXT NOT NULL CHECK (last_seen GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    expires_at TEXT NOT NULL CHECK (expires_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    revoked_at TEXT CHECK (revoked_at IS NULL OR revoked_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z')
);

CREATE TABLE core_org (
    id             INTEGER NOT NULL PRIMARY KEY CHECK (id = 1),
    name           TEXT    NOT NULL CHECK (length(name) BETWEEN 1 AND 200),
    timezone       TEXT    NOT NULL DEFAULT 'Asia/Ho_Chi_Minh' CHECK (length(timezone) BETWEEN 1 AND 64),
    setup_complete INTEGER NOT NULL DEFAULT 0 CHECK (setup_complete IN (0, 1)),
    data_mode      TEXT    NOT NULL DEFAULT 'clean' CHECK (data_mode IN ('sample', 'clean')),
    install_id     TEXT    NOT NULL CHECK (length(install_id) BETWEEN 1 AND 96)
);

CREATE TABLE core_setting (
    key        TEXT NOT NULL PRIMARY KEY CHECK (length(key) BETWEEN 1 AND 96),
    value      TEXT NOT NULL CHECK (json_valid(value)),
    updated_at TEXT NOT NULL CHECK (updated_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    updated_by TEXT NOT NULL CHECK (length(updated_by) BETWEEN 1 AND 320)
);

CREATE TABLE core_chain_head (
    chain      TEXT    NOT NULL PRIMARY KEY CHECK (chain IN ('core_audit', 'ai_activity', 'resp_log')),
    last_hash  TEXT    NOT NULL CHECK (length(last_hash) = 64),
    count      INTEGER NOT NULL CHECK (count >= 0),
    updated_at TEXT    NOT NULL CHECK (updated_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z')
);

CREATE TABLE core_connection (
    id         TEXT    NOT NULL PRIMARY KEY CHECK (length(id) BETWEEN 1 AND 96),
    name       TEXT    NOT NULL CHECK (length(name) BETWEEN 1 AND 40),
    name_key   TEXT    NOT NULL UNIQUE CHECK (length(name_key) BETWEEN 1 AND 160), -- the name in lower case for every script: names are unique in any letter case
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
    enabled       BOOLEAN NOT NULL CHECK (enabled IN (0, 1)), ident TEXT NOT NULL DEFAULT '' CHECK (length(ident) <= 64),
    PRIMARY KEY (connection_id, name)
) WITHOUT ROWID;

CREATE TABLE core_sensor_cert (
    serial     TEXT NOT NULL PRIMARY KEY CHECK (length(serial) BETWEEN 1 AND 64 AND serial NOT GLOB '*[^0-9a-f]*'), -- hex of the x509 serial
    role       TEXT NOT NULL CHECK (role IN ('passive', 'active')),
    not_after  TEXT NOT NULL CHECK (not_after GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    retired_at TEXT CHECK (retired_at IS NULL OR retired_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z')
);

CREATE INDEX core_audit_ts_idx ON core_audit (ts);

CREATE INDEX core_job_run_job_idx ON core_job_run (module, job, started_at);

CREATE INDEX core_user_role_idx ON core_user (role);

CREATE INDEX core_email_code_send_user_idx ON core_email_code_send (user_id, sent_at);

CREATE INDEX core_session_user_idx ON core_session (user_id);

CREATE INDEX core_sensor_cert_live ON core_sensor_cert (role) WHERE retired_at IS NULL;

CREATE UNIQUE INDEX core_user_sso_idx ON core_user (sso_issuer, sso_subject) WHERE sso_issuer IS NOT NULL;

-- +goose StatementBegin
CREATE TRIGGER core_audit_no_update BEFORE UPDATE ON core_audit
BEGIN
    SELECT RAISE(ABORT, 'core_audit is append-only');
END;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TRIGGER core_audit_no_replace BEFORE INSERT ON core_audit
WHEN EXISTS (SELECT 1 FROM core_audit WHERE id = NEW.id OR hash = NEW.hash OR seq = NEW.seq)
BEGIN
    SELECT RAISE(ABORT, 'core_audit is append-only');
END;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TRIGGER core_audit_no_delete BEFORE DELETE ON core_audit
WHEN OLD.seq > COALESCE((SELECT a.seq FROM core_audit a JOIN core_chain_anchor c ON c.last_pruned_id = a.id WHERE c.chain = 'core_audit'), 0)
BEGIN
    SELECT RAISE(ABORT, 'core_audit is append-only');
END;
-- +goose StatementEnd

-- ---------------------------------------------------------------------------------------------------------------------------
-- Runs: one model for every piece of scanning work a person can see (core/run). The queue is the rows in status 'queued', so it
-- survives a restart. kind and status are open vocabularies owned by core/run (shape check only); lane is what a run occupies,
-- and the database holds one live run per lane (core_run_live). Module detail stays in module tables keyed by run_id.
-- schedule_id is the schedule that came due (core_schedule, the section below); a deleted schedule leaves its runs.
-- ---------------------------------------------------------------------------------------------------------------------------

CREATE TABLE core_run (
    id            TEXT    NOT NULL PRIMARY KEY CHECK (length(id) BETWEEN 1 AND 96),
    module        TEXT    NOT NULL CHECK (length(module) BETWEEN 1 AND 32),
    kind          TEXT    NOT NULL CHECK (length(kind) BETWEEN 1 AND 40 AND kind NOT GLOB '*[^a-z0-9_]*'),
    lane          TEXT    NOT NULL CHECK (length(lane) BETWEEN 1 AND 40 AND lane NOT GLOB '*[^a-z0-9_]*'),
    title         TEXT    NOT NULL CHECK (length(title) BETWEEN 1 AND 200),
    trigger       TEXT    NOT NULL CHECK (trigger IN ('manual', 'schedule', 'event')),
    trigger_note  TEXT    CHECK (trigger_note IS NULL OR length(trigger_note) BETWEEN 1 AND 200),
    requested_by  TEXT    NOT NULL CHECK (length(requested_by) BETWEEN 1 AND 320), -- an email, or system
    schedule_id   TEXT    REFERENCES core_schedule (id) ON DELETE SET NULL,
    subject_kind  TEXT    CHECK (subject_kind IS NULL OR (length(subject_kind) BETWEEN 1 AND 40 AND subject_kind NOT GLOB '*[^a-z0-9_]*')),
    subject_id    TEXT    CHECK (subject_id IS NULL OR length(subject_id) BETWEEN 1 AND 96),
    subject_label TEXT    CHECK (subject_label IS NULL OR length(subject_label) BETWEEN 1 AND 200), -- a snapshot: it outlives its subject
    parent_id     TEXT    REFERENCES core_run (id) ON DELETE CASCADE,
    status        TEXT    NOT NULL CHECK (length(status) BETWEEN 1 AND 40 AND status NOT GLOB '*[^a-z0-9_]*'),
    waiting_for   TEXT    CHECK (waiting_for IS NULL OR length(waiting_for) BETWEEN 1 AND 200),
    stop_reason   TEXT    CHECK (stop_reason IS NULL OR length(stop_reason) BETWEEN 1 AND 500),
    error         TEXT    CHECK (error IS NULL OR length(error) BETWEEN 1 AND 1000),
    total         INTEGER NOT NULL DEFAULT 0 CHECK (total >= 0),
    done          INTEGER NOT NULL DEFAULT 0 CHECK (done >= 0),
    queued_at     TEXT    NOT NULL CHECK (queued_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    started_at    TEXT    CHECK (started_at IS NULL OR started_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    ended_at      TEXT    CHECK (ended_at IS NULL OR ended_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    updated_at    TEXT    NOT NULL CHECK (updated_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    CHECK ((subject_kind IS NULL) = (subject_id IS NULL))
);

-- A phase or a range of a run ("192.168.1.0/24", "identify services"): the cursor a resumed run continues from.
CREATE TABLE core_run_step (
    run_id     TEXT    NOT NULL REFERENCES core_run (id) ON DELETE CASCADE,
    seq        INTEGER NOT NULL CHECK (seq >= 1),
    name       TEXT    NOT NULL CHECK (length(name) BETWEEN 1 AND 200),
    status     TEXT    NOT NULL CHECK (length(status) BETWEEN 1 AND 40 AND status NOT GLOB '*[^a-z0-9_]*'),
    total      INTEGER NOT NULL DEFAULT 0 CHECK (total >= 0),
    done       INTEGER NOT NULL DEFAULT 0 CHECK (done >= 0),
    note       TEXT    CHECK (note IS NULL OR length(note) BETWEEN 1 AND 500),
    started_at TEXT    CHECK (started_at IS NULL OR started_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    ended_at   TEXT    CHECK (ended_at IS NULL OR ended_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    PRIMARY KEY (run_id, seq)
) WITHOUT ROWID;

-- One row per device or host a run touched, as it comes.
CREATE TABLE core_run_item (
    run_id       TEXT    NOT NULL REFERENCES core_run (id) ON DELETE CASCADE,
    seq          INTEGER NOT NULL CHECK (seq >= 1),
    subject_kind TEXT    NOT NULL CHECK (length(subject_kind) BETWEEN 1 AND 40 AND subject_kind NOT GLOB '*[^a-z0-9_]*'),
    subject_id   TEXT    CHECK (subject_id IS NULL OR length(subject_id) BETWEEN 1 AND 96), -- NULL: an address no device has yet
    label        TEXT    NOT NULL CHECK (length(label) BETWEEN 1 AND 200),
    outcome      TEXT    NOT NULL CHECK (length(outcome) BETWEEN 1 AND 40 AND outcome NOT GLOB '*[^a-z0-9_]*'),
    note         TEXT    CHECK (note IS NULL OR length(note) BETWEEN 1 AND 500),
    PRIMARY KEY (run_id, seq)
) WITHOUT ROWID;

-- The log of a run: at most 2,000 lines per run and 30 days (core/run Prune).
CREATE TABLE core_run_log (
    id     INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    run_id TEXT    NOT NULL REFERENCES core_run (id) ON DELETE CASCADE,
    ts     TEXT    NOT NULL CHECK (ts GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    level  TEXT    NOT NULL CHECK (level IN ('info', 'warn', 'error')),
    text   TEXT    NOT NULL CHECK (length(text) BETWEEN 1 AND 1000)
);

-- One live run per lane, held by the database: a second start in the same lane fails here, whatever the code does.
CREATE UNIQUE INDEX core_run_live ON core_run (lane) WHERE status IN ('running', 'stopping');

CREATE INDEX core_run_queued_idx ON core_run (queued_at);

CREATE INDEX core_run_status_idx ON core_run (status, queued_at);

CREATE INDEX core_run_subject_idx ON core_run (subject_kind, subject_id, queued_at);

CREATE INDEX core_run_kind_idx ON core_run (module, kind, queued_at);

CREATE INDEX core_run_parent_idx ON core_run (parent_id);

CREATE INDEX core_run_log_run_idx ON core_run_log (run_id, id);

CREATE INDEX core_run_log_ts_idx ON core_run_log (ts);

CREATE INDEX core_run_schedule_idx ON core_run (schedule_id);

-- ---------------------------------------------------------------------------------------------------------------------------
-- Schedules: one model for every schedule a person can set (core/schedule). owner_key names what the schedule starts
-- ('scan.vuln', 'exposure.target:<id>', ...); its owner registers in code what it allows. freq is an open vocabulary owned by
-- core/schedule (shape check only); the rule columns a frequency does not use are NULL. next_due_at is written by core/schedule
-- alone, in the same transaction as any change of the rule or any due time: it is Next(rule) from the latest of last_due_at,
-- updated_at and paused_until (schedule.Due), and NULL while the schedule is off or never comes due again.
-- ---------------------------------------------------------------------------------------------------------------------------

CREATE TABLE core_schedule (
    id               TEXT    NOT NULL PRIMARY KEY CHECK (length(id) BETWEEN 1 AND 96),
    owner_module     TEXT    NOT NULL CHECK (length(owner_module) BETWEEN 1 AND 32),
    owner_key        TEXT    NOT NULL UNIQUE CHECK (length(owner_key) BETWEEN 1 AND 160),
    enabled          INTEGER NOT NULL CHECK (enabled IN (0, 1)),
    paused_until     TEXT    CHECK (paused_until IS NULL OR paused_until GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    freq             TEXT    NOT NULL CHECK (length(freq) BETWEEN 1 AND 40 AND freq NOT GLOB '*[^a-z0-9_]*'),
    every_minutes    INTEGER CHECK (every_minutes IS NULL OR every_minutes BETWEEN 1 AND 527040),
    at_time          TEXT    CHECK (at_time IS NULL OR at_time GLOB '[0-2][0-9]:[0-5][0-9]'),
    weekdays         TEXT    CHECK (weekdays IS NULL OR (json_valid(weekdays) AND json_type(weekdays) = 'array')), -- [1..7], 1 = Monday
    month_day        INTEGER CHECK (month_day IS NULL OR month_day BETWEEN 0 AND 31),                                 -- 0 = the last day
    once_at          TEXT    CHECK (once_at IS NULL OR once_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    tz               TEXT    NOT NULL CHECK (length(tz) BETWEEN 1 AND 64),                                             -- 'org' or an IANA zone
    window_mode      TEXT    NOT NULL CHECK (window_mode IN ('global', 'none', 'custom')),
    window_days      TEXT    CHECK (window_days IS NULL OR (json_valid(window_days) AND json_type(window_days) = 'array')),
    window_from      TEXT    CHECK (window_from IS NULL OR window_from GLOB '[0-2][0-9]:[0-5][0-9]'),
    window_to        TEXT    CHECK (window_to IS NULL OR window_to GLOB '[0-2][0-9]:[0-5][0-9]'),
    next_due_at      TEXT    CHECK (next_due_at IS NULL OR next_due_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    last_due_at      TEXT    CHECK (last_due_at IS NULL OR last_due_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    last_run_id      TEXT    REFERENCES core_run (id) ON DELETE SET NULL,
    last_skip_reason TEXT    CHECK (last_skip_reason IS NULL OR length(last_skip_reason) BETWEEN 1 AND 300),
    last_skip_at     TEXT    CHECK (last_skip_at IS NULL OR last_skip_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    updated_by       TEXT    NOT NULL CHECK (length(updated_by) BETWEEN 1 AND 320), -- an email, or system
    updated_at       TEXT    NOT NULL CHECK (updated_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    CHECK (enabled = 1 OR next_due_at IS NULL),
    CHECK ((last_skip_reason IS NULL) = (last_skip_at IS NULL)),
    CHECK (window_mode = 'custom' OR (window_days IS NULL AND window_from IS NULL AND window_to IS NULL)),
    CHECK (window_mode <> 'custom' OR (window_days IS NOT NULL AND window_from IS NOT NULL AND window_to IS NOT NULL))
);

CREATE INDEX core_schedule_due_idx ON core_schedule (enabled, next_due_at);

CREATE INDEX core_schedule_last_run_idx ON core_schedule (last_run_id);
