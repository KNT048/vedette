-- +goose Up
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
INSERT INTO logs_siem (id, enabled, format, host, port, proto, url, secret_id, secret_last4, events, last_test)
VALUES (1, 0, 'syslog', '', 514, 'udp', '', NULL, NULL, '["findings","alerts"]', NULL);
