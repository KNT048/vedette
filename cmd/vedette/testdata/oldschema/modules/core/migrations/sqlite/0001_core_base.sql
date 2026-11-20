-- +goose Up
-- Core base: secrets (docs/DATA_MODEL.md 5.4) and the hash-chained audit log (5.3).
-- Forward-only (DATA_MODEL 6, rule 1): there is deliberately no Down section.

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

CREATE INDEX core_audit_ts_idx ON core_audit (ts);

-- Append-only at the database level (INV-2). Retention pruning needs its own path.
-- +goose StatementBegin
CREATE TRIGGER core_audit_no_update BEFORE UPDATE ON core_audit
BEGIN
    SELECT RAISE(ABORT, 'core_audit is append-only');
END;
-- +goose StatementEnd

-- REPLACE / INSERT OR REPLACE delete the conflicting row without firing the DELETE trigger, and
-- INSERT ... ON CONFLICT DO UPDATE would rewrite it: refuse any insert that collides with an existing row.
-- (BEFORE INSERT runs before the conflict is resolved.)
-- +goose StatementBegin
CREATE TRIGGER core_audit_no_replace BEFORE INSERT ON core_audit
WHEN EXISTS (SELECT 1 FROM core_audit WHERE id = NEW.id OR hash = NEW.hash OR seq = NEW.seq)
BEGIN
    SELECT RAISE(ABORT, 'core_audit is append-only');
END;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TRIGGER core_audit_no_delete BEFORE DELETE ON core_audit
BEGIN
    SELECT RAISE(ABORT, 'core_audit is append-only');
END;
-- +goose StatementEnd

CREATE TABLE core_chain_anchor (
    chain            TEXT NOT NULL PRIMARY KEY CHECK (chain IN ('core_audit', 'ai_activity', 'resp_log')),
    last_pruned_id   TEXT NOT NULL,
    last_pruned_hash TEXT NOT NULL CHECK (length(last_pruned_hash) = 64),
    pruned_at        TEXT NOT NULL CHECK (pruned_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z')
);
