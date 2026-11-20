-- +goose Up
-- The whole schema of the logs module in the main database. It is edited in place until the first public release; docs/SCHEMA.sql
-- shows the schema of every module together. Forward-only: there is no Down section.

CREATE TABLE logs_sources (
    id         TEXT NOT NULL PRIMARY KEY CHECK (length(id) BETWEEN 1 AND 64),
    kind       TEXT NOT NULL CHECK (length(kind) BETWEEN 1 AND 32),
    name       TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 64),
    sender_ip  TEXT NOT NULL CHECK (length(sender_ip) BETWEEN 7 AND 15),
    proto      TEXT NOT NULL CHECK (proto IN ('udp', 'tcp', 'tls')),
    port       INTEGER NOT NULL CHECK (port BETWEEN 1 AND 65535),
    created_at TEXT NOT NULL CHECK (created_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z')
, signatures_since TEXT CHECK (signatures_since IS NULL OR signatures_since GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'), client_cert_sha256 TEXT NOT NULL DEFAULT '' CHECK (client_cert_sha256 = '' OR (length(client_cert_sha256) = 64 AND client_cert_sha256 NOT GLOB '*[^0-9a-f]*'))) WITHOUT ROWID;

-- one row: how long received lines are kept (INV-4)
CREATE TABLE logs_retention (
    id   INTEGER NOT NULL PRIMARY KEY CHECK (id = 1),
    days INTEGER NOT NULL CHECK (days IN (7, 30, 90, 180))
);

-- SIEM forwarding (L5, S-LOG-3): one row, in the main database so that a change is audited in the same transaction (SYS-3) and the
-- row is part of the backup. The signing key is not here: secret_id names a sealed core_secret (SYS-4), secret_last4 is all the API shows.
-- Off by default: nothing is sent until an administrator saves a destination and turns it on (INV-8, FORBID-3).
CREATE TABLE logs_siem (
    id           INTEGER NOT NULL PRIMARY KEY CHECK (id = 1),
    enabled      INTEGER NOT NULL CHECK (enabled IN (0, 1)),
    format       TEXT    NOT NULL CHECK (format IN ('syslog', 'cef', 'json')),
    host         TEXT    NOT NULL CHECK (length(host) <= 253),
    port         INTEGER NOT NULL CHECK (port BETWEEN 1 AND 65535),
    proto        TEXT    NOT NULL CHECK (proto IN ('udp', 'tcp', 'tls')),
    url          TEXT    NOT NULL CHECK (length(url) <= 2048),
    secret_id    TEXT    REFERENCES core_secret (id),
    secret_last4 TEXT    CHECK (secret_last4 IS NULL OR length(secret_last4) = 4),
    events       TEXT    NOT NULL CHECK (json_valid(events)),
    last_test    TEXT    CHECK (last_test IS NULL OR json_valid(last_test))
);

-- one source per sender address (the mock answers 409 duplicate)
CREATE UNIQUE INDEX logs_sources_sender_uq ON logs_sources (sender_ip);

INSERT INTO logs_retention (id, days) VALUES (1, 30);

INSERT INTO logs_siem (id, enabled, format, host, port, proto, url, events) VALUES (1, 0, 'syslog', '', 514, 'udp', '', '["findings","alerts"]');
