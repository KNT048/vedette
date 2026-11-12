-- +goose Up
-- Connections from a LAN device to an address or name that a threat feed lists (L4, S-LOG-2, S-LOG-4, INV-7, D-213). One row per
-- (src_ip, dest) per 24 hours (a device that keeps talking to the same address is one hit, not one per line), at most 10,000 rows (the
-- oldest go first), and kept as long as the module's retention. asset_id is NOT stored: the device with src_ip is looked up in the inventory when
-- the row is read, so a device that is renamed or deleted never shows a stale name (INV-7). feeds is a JSON array of the names of the
-- feeds that listed the destination when the line came in; source_id is the log source whose line it was (the id only: the source may be
-- deleted while its hits stay).
CREATE TABLE logs_ioc_hits (
    id         TEXT    PRIMARY KEY CHECK (length(id) BETWEEN 1 AND 64),
    ts         TEXT    NOT NULL,
    src_ip     TEXT    NOT NULL CHECK (length(src_ip) BETWEEN 7 AND 15),
    dest       TEXT    NOT NULL CHECK (length(dest) BETWEEN 1 AND 253),
    dest_kind  TEXT    NOT NULL CHECK (dest_kind IN ('ip', 'domain')),
    seen_via   TEXT    NOT NULL CHECK (length(seen_via) BETWEEN 1 AND 128),
    feeds      TEXT    NOT NULL CHECK (json_valid(feeds)),
    confidence REAL    NOT NULL CHECK (confidence BETWEEN 0 AND 1),
    source_id  TEXT    NOT NULL CHECK (length(source_id) BETWEEN 1 AND 64)
);
CREATE INDEX logs_ioc_hits_ts ON logs_ioc_hits (ts);
CREATE INDEX logs_ioc_hits_pair ON logs_ioc_hits (src_ip, dest, ts);
