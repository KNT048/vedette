-- +goose Up
-- The whole schema of the ids module. It is edited in place until the first public release; docs/SCHEMA.sql
-- shows the schema of every module together. Forward-only: there is no Down section.

-- One intrusion alert: the IPS or IDS events of one signature, from one source address to one destination address, within one
-- hour (dedupe_key). source is where the box saw them (an open vocabulary: log = an IPS event in a received firewall log line).
-- The device columns are the inventory devices that had the addresses when the events arrived; a deleted device leaves NULL.
CREATE TABLE ids_alert (
    id           TEXT    NOT NULL PRIMARY KEY CHECK (length(id) BETWEEN 1 AND 64),
    source       TEXT    NOT NULL CHECK (length(source) BETWEEN 1 AND 40 AND source NOT GLOB '*[^a-z0-9_]*'),
    sid          INTEGER CHECK (sid IS NULL OR sid >= 0),
    signature    TEXT    NOT NULL CHECK (length(signature) BETWEEN 1 AND 300),
    category     TEXT    NOT NULL DEFAULT '' CHECK (length(category) <= 120),
    priority     INTEGER NOT NULL CHECK (priority BETWEEN 1 AND 4),
    src_ip       TEXT    NOT NULL CHECK (length(src_ip) BETWEEN 2 AND 45),
    dst_ip       TEXT    NOT NULL CHECK (length(dst_ip) BETWEEN 2 AND 45),
    dst_port     INTEGER CHECK (dst_port IS NULL OR dst_port BETWEEN 0 AND 65535),
    proto        TEXT    NOT NULL DEFAULT '' CHECK (length(proto) <= 16),
    src_asset_id TEXT    REFERENCES inv_asset (id) ON DELETE SET NULL,
    dst_asset_id TEXT    REFERENCES inv_asset (id) ON DELETE SET NULL,
    first_ts     TEXT    NOT NULL CHECK (first_ts GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    last_ts      TEXT    NOT NULL CHECK (last_ts GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    count        INTEGER NOT NULL CHECK (count >= 1),
    dedupe_key   TEXT    NOT NULL UNIQUE CHECK (length(dedupe_key) = 64),
    CHECK (last_ts >= first_ts)
) STRICT;

CREATE INDEX ids_alert_last_ix ON ids_alert (last_ts);
CREATE INDEX ids_alert_src_asset_ix ON ids_alert (src_asset_id) WHERE src_asset_id IS NOT NULL;
CREATE INDEX ids_alert_dst_asset_ix ON ids_alert (dst_asset_id) WHERE dst_asset_id IS NOT NULL;

-- The CVE ids an alert's events name: the attack <-> vulnerability link findings reads through the ids module's port.
CREATE TABLE ids_alert_cve (
    alert_id TEXT NOT NULL REFERENCES ids_alert (id) ON DELETE CASCADE,
    cve      TEXT NOT NULL CHECK (cve GLOB 'CVE-[0-9][0-9][0-9][0-9]-[0-9][0-9][0-9][0-9]*' AND length(cve) <= 20),
    PRIMARY KEY (alert_id, cve)
) STRICT, WITHOUT ROWID;

CREATE INDEX ids_alert_cve_cve_ix ON ids_alert_cve (cve);
