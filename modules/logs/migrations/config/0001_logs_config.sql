-- +goose Up
-- Configuration of the logs module, in the main database (vedette.db) so that it is audited in the same transaction as
-- the change (SYS-3) and is part of the backup. The volume (events, counters) is in logs.db (migrations/volume).
-- Forward-only (DATA_MODEL 6, rule 1).

CREATE TABLE logs_sources (
    id         TEXT NOT NULL PRIMARY KEY CHECK (length(id) BETWEEN 1 AND 64),
    kind       TEXT NOT NULL CHECK (length(kind) BETWEEN 1 AND 32),
    name       TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 64),
    sender_ip  TEXT NOT NULL CHECK (length(sender_ip) BETWEEN 7 AND 15),
    proto      TEXT NOT NULL CHECK (proto IN ('udp', 'tcp', 'tls')),
    port       INTEGER NOT NULL CHECK (port BETWEEN 1 AND 65535),
    created_at TEXT NOT NULL CHECK (created_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z')
) WITHOUT ROWID;
-- one source per sender address (the mock answers 409 duplicate)
CREATE UNIQUE INDEX logs_sources_sender_uq ON logs_sources (sender_ip);

-- one row: how long received lines are kept (INV-4)
CREATE TABLE logs_retention (
    id   INTEGER NOT NULL PRIMARY KEY CHECK (id = 1),
    days INTEGER NOT NULL CHECK (days IN (7, 30, 90, 180))
);
INSERT INTO logs_retention (id, days) VALUES (1, 30);
