-- +goose Up
-- Core auth: users, two-step state, sessions, the organisation row and settings (docs/DATA_MODEL.md section 3).
-- Forward-only (DATA_MODEL 6, rule 1): there is deliberately no Down section.

CREATE TABLE core_user (
    id            TEXT    NOT NULL PRIMARY KEY CHECK (length(id) BETWEEN 1 AND 96),
    name          TEXT    NOT NULL CHECK (length(name) BETWEEN 1 AND 200),
    email         TEXT    NOT NULL UNIQUE CHECK (email = lower(email) AND length(email) BETWEEN 3 AND 320),
    role          TEXT    NOT NULL CHECK (role IN ('viewer', 'operator', 'admin')),
    password_hash TEXT    NOT NULL CHECK (length(password_hash) BETWEEN 1 AND 512), -- argon2id PHC string
    twofa_method  TEXT    CHECK (twofa_method IS NULL OR twofa_method IN ('app', 'email')),
    disabled      INTEGER NOT NULL DEFAULT 0 CHECK (disabled IN (0, 1)),
    created_at    TEXT    NOT NULL CHECK (created_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    last_login    TEXT    CHECK (last_login IS NULL OR last_login GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z')
);

CREATE INDEX core_user_role_idx ON core_user (role);

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
    code_hash  TEXT    NOT NULL CHECK (length(code_hash) = 64), -- SHA-256 of the 6 digits
    expires_at TEXT    NOT NULL CHECK (expires_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    tries      INTEGER NOT NULL DEFAULT 0 CHECK (tries BETWEEN 0 AND 5),
    sent_at    TEXT    NOT NULL CHECK (sent_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z')
);

CREATE TABLE core_email_code_send (
    user_id TEXT NOT NULL REFERENCES core_user (id) ON DELETE CASCADE,
    sent_at TEXT NOT NULL CHECK (sent_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z')
);

CREATE INDEX core_email_code_send_user_idx ON core_email_code_send (user_id, sent_at);

CREATE TABLE core_session (
    id         TEXT NOT NULL PRIMARY KEY CHECK (length(id) BETWEEN 1 AND 96),
    user_id    TEXT NOT NULL REFERENCES core_user (id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL UNIQUE CHECK (length(token_hash) = 64), -- SHA-256 of the vedette_session cookie
    csrf_hash  TEXT NOT NULL CHECK (length(csrf_hash) = 64),         -- SHA-256 of the vedette_csrf cookie
    device     TEXT NOT NULL CHECK (length(device) <= 200),
    ip         TEXT NOT NULL CHECK (length(ip) BETWEEN 1 AND 64),
    started_at TEXT NOT NULL CHECK (started_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    last_seen  TEXT NOT NULL CHECK (last_seen GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    expires_at TEXT NOT NULL CHECK (expires_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    revoked_at TEXT CHECK (revoked_at IS NULL OR revoked_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z')
);

CREATE INDEX core_session_user_idx ON core_session (user_id);

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
