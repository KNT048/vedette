-- +goose NO TRANSACTION
-- +goose Up
-- D-511: device types have two levels and come from one list (content/devicetypes/types.json, 89 types acting as the 13 kinds of
-- before). The literal CHECK on inv_asset.kind becomes a format check; the inventory validates the type against the list (validKind),
-- as it already did for every observation. SQLite cannot change a CHECK, so inv_asset is rebuilt with the same columns, ids and
-- indexes. inv_asset is the parent of ON DELETE CASCADE keys (inv_observation, inv_service, inv_software): with foreign keys on,
-- DROP TABLE inv_asset would delete every child row. So this migration runs outside goose's transaction, turns foreign keys off on
-- its own connection and makes its own transaction, the documented SQLite procedure
-- (https://www.sqlite.org/lang_altertable.html#otheralter), as findings 0005 does. The children keep "REFERENCES inv_asset" and point
-- at the new table once it has the name.
-- inv_asset.first_scan_at: see the UPDATE below.
-- inv_service.detail: what an open service said about the device besides its product and version (nmap's extra info and device
-- type, the page title, the certificate subject): evidence for identification, never software (D-511).
-- Forward-only (DATA_MODEL 6, rule 1).
PRAGMA foreign_keys = OFF;

BEGIN IMMEDIATE;

DROP TABLE IF EXISTS inv_asset_new;
CREATE TABLE inv_asset_new (
    id             TEXT    NOT NULL PRIMARY KEY CHECK (length(id) BETWEEN 1 AND 96),
    ip             TEXT    CHECK (ip IS NULL OR length(ip) BETWEEN 7 AND 15),
    mac            TEXT    CHECK (mac IS NULL OR length(mac) = 17),
    hostname       TEXT    CHECK (hostname IS NULL OR length(hostname) BETWEEN 1 AND 253),
    kind           TEXT    NOT NULL DEFAULT 'unknown' CHECK (length(kind) BETWEEN 1 AND 40 AND kind NOT GLOB '*[^a-z0-9_]*'),
    vendor         TEXT    CHECK (vendor IS NULL OR length(vendor) <= 200),
    model          TEXT    CHECK (model IS NULL OR length(model) <= 200),
    os             TEXT    CHECK (os IS NULL OR length(os) <= 200),
    vendor_obs_id  TEXT,
    model_obs_id   TEXT,
    os_obs_id      TEXT,
    kind_obs_id    TEXT,
    hostname_obs_id TEXT,
    mac_obs_id     TEXT,
    origin         TEXT    NOT NULL CHECK (origin IN ('discovered', 'manual')),
    approved       BOOLEAN NOT NULL DEFAULT 0 CHECK (approved IN (0, 1)),
    fragile        BOOLEAN NOT NULL DEFAULT 0 CHECK (fragile IN (0, 1)),
    fragile_manual BOOLEAN NOT NULL DEFAULT 0 CHECK (fragile_manual IN (0, 1)),
    regular_scan   TEXT    NOT NULL DEFAULT 'follow' CHECK (regular_scan IN ('follow', 'allow', 'never')),
    first_scan_at  TEXT    CHECK (first_scan_at IS NULL OR first_scan_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    suspicious     BOOLEAN NOT NULL DEFAULT 0 CHECK (suspicious IN (0, 1)),
    is_box         BOOLEAN NOT NULL DEFAULT 0 CHECK (is_box IN (0, 1)),
    notes          TEXT    CHECK (notes IS NULL OR length(notes) <= 2000),
    first_seen     TEXT    NOT NULL CHECK (first_seen GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    last_seen      TEXT    NOT NULL CHECK (last_seen GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    approved_at    TEXT    CHECK (approved_at IS NULL OR approved_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z')
);
INSERT INTO inv_asset_new (id, ip, mac, hostname, kind, vendor, model, os, vendor_obs_id, model_obs_id, os_obs_id, kind_obs_id, hostname_obs_id,
        mac_obs_id, origin, approved, fragile, fragile_manual, regular_scan, first_scan_at, suspicious, is_box, notes, first_seen, last_seen, approved_at)
    SELECT id, ip, mac, hostname, kind, vendor, model, os, vendor_obs_id, model_obs_id, os_obs_id, kind_obs_id, hostname_obs_id,
        mac_obs_id, origin, approved, fragile, fragile_manual, regular_scan, first_scan_at, suspicious, is_box, notes, first_seen, last_seen, approved_at
    FROM inv_asset ORDER BY rowid;
DROP TABLE inv_asset;
ALTER TABLE inv_asset_new RENAME TO inv_asset;
CREATE UNIQUE INDEX inv_asset_ip_uq ON inv_asset (ip) WHERE ip IS NOT NULL;
CREATE UNIQUE INDEX inv_asset_box_uq ON inv_asset (is_box) WHERE is_box = 1;
CREATE INDEX inv_asset_hostname_ix ON inv_asset (lower(hostname)) WHERE hostname IS NOT NULL;
CREATE UNIQUE INDEX inv_asset_mac_uq ON inv_asset (mac) WHERE mac IS NOT NULL;
CREATE INDEX inv_asset_kind_ix ON inv_asset (kind);
CREATE INDEX inv_asset_approved_ix ON inv_asset (approved);
CREATE INDEX inv_asset_last_seen_ix ON inv_asset (last_seen);

ALTER TABLE inv_service ADD COLUMN detail TEXT CHECK (detail IS NULL OR length(detail) <= 200);

-- Lead decision on #714: the gentle scan of a device of unknown kind that nobody made fragile now also reads its page titles and
-- certificates (sensor-active gentle_titles). A device that had its gentle scan before gets that one scan again, so what it states
-- (a FortiGate's certificate, J-Web's title) shows without a Scan now: one more scan at 1 packet per second, never for a fragile
-- device, a device set to "never", one declared by hand or the box.
UPDATE inv_asset SET first_scan_at = NULL
WHERE kind = 'unknown' AND fragile = 0 AND origin = 'discovered' AND is_box = 0 AND regular_scan <> 'never' AND first_scan_at IS NOT NULL;

COMMIT;

PRAGMA foreign_keys = ON;
