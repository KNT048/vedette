-- +goose Up
-- D-467: more trap services (https, ftp, telnet, mysql, mongodb, redis, vnc, git, httpproxy, tcpbanner, tftp, ntp, sip). A hit may
-- name any of them, and hp_config gets the key "https": the id of the core_secret row that holds the HTTPS trap's certificate and
-- key (never the key itself). A hit gets `handshake`: 0 for a UDP service hit (TFTP, NTP, SIP have no handshake, so the source can be
-- forged: such a hit never confirms a source, D-467 review H1), 1 for every other hit and every hit stored before. SQLite cannot
-- change a CHECK, so both tables are rebuilt with the same rows. Trap IPs keep exactly the services they have. Forward-only
-- (DATA_MODEL 6, rule 1); an older core still runs on it (D-138): modules/honeypot IMPACT says what it does with the new rows.
CREATE TABLE hp_config_new (
    key        TEXT NOT NULL PRIMARY KEY CHECK (key IN ('applied', 'tail', 'https')),
    value      TEXT NOT NULL CHECK (json_valid(value)),
    updated_at TEXT NOT NULL CHECK (updated_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    updated_by TEXT NOT NULL CHECK (length(updated_by) > 0)
) STRICT;
INSERT INTO hp_config_new (key, value, updated_at, updated_by)
    SELECT key, value, updated_at, updated_by FROM hp_config WHERE key IN ('applied', 'tail');
DROP TABLE hp_config;
ALTER TABLE hp_config_new RENAME TO hp_config;

CREATE TABLE hp_hits_new (
    id             TEXT    NOT NULL PRIMARY KEY CHECK (length(id) BETWEEN 1 AND 96),
    ts             TEXT    NOT NULL CHECK (ts GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    kind           TEXT    NOT NULL CHECK (kind IN ('service', 'token', 'scan')),
    service        TEXT    CHECK (service IS NULL OR service IN ('smb', 'rdp', 'ssh', 'mssql', 'http', 'https', 'ftp', 'telnet', 'mysql',
                                                             'mongodb', 'redis', 'vnc', 'git', 'httpproxy', 'tcpbanner', 'tftp', 'ntp', 'sip')),
    label          TEXT    NOT NULL CHECK (length(label) <= 200),
    port           INTEGER CHECK (port IS NULL OR port BETWEEN 1 AND 65535),
    src_ip         TEXT    NOT NULL CHECK (length(src_ip) BETWEEN 7 AND 15),
    source_ip      TEXT    GENERATED ALWAYS AS (src_ip) VIRTUAL,
    is_test        INTEGER NOT NULL DEFAULT 0 CHECK (is_test IN (0, 1)),
    excerpt        TEXT    NOT NULL CHECK (length(excerpt) <= 1000),
    trap_ip        TEXT    NOT NULL CHECK (length(trap_ip) <= 400),
    trap_hostname  TEXT    NOT NULL CHECK (length(trap_hostname) <= 200),
    token_id       TEXT    CHECK (token_id IS NULL OR length(token_id) <= 96),
    events         TEXT    NOT NULL DEFAULT '[]' CHECK (json_valid(events)),
    conn_key       TEXT    UNIQUE CHECK (conn_key IS NULL OR length(conn_key) = 64),
    conn_count     INTEGER NOT NULL DEFAULT 1 CHECK (conn_count >= 1),
    handshake      INTEGER NOT NULL DEFAULT 1 CHECK (handshake IN (0, 1))
) STRICT;
INSERT INTO hp_hits_new (id, ts, kind, service, label, port, src_ip, is_test, excerpt, trap_ip, trap_hostname, token_id, events, conn_key, conn_count)
    SELECT id, ts, kind, service, label, port, src_ip, is_test, excerpt, trap_ip, trap_hostname, token_id, events, conn_key, conn_count FROM hp_hits;
DROP TABLE hp_hits;
ALTER TABLE hp_hits_new RENAME TO hp_hits;
CREATE INDEX hp_hits_ts_ix ON hp_hits (ts DESC);
CREATE INDEX hp_hits_src_ix ON hp_hits (src_ip);
CREATE INDEX hp_hits_token_ix ON hp_hits (token_id) WHERE token_id IS NOT NULL;
