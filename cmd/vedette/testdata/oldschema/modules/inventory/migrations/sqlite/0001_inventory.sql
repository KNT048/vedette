-- +goose Up
-- Inventory tables (docs/DATA_MODEL.md 4.2, 5.1). Forward-only (DATA_MODEL 6, rule 1): no Down section.
-- Only inventory.Service writes these tables (INV-2).

-- A device. The "current" columns (hostname, mac, vendor, model, os, kind and their *_obs_id) are the fold of
-- inv_observation and are written only by Service.RecomputeAsset (DATA_MODEL 5.1 rule 3).
CREATE TABLE inv_asset (
    id             TEXT    NOT NULL PRIMARY KEY CHECK (length(id) BETWEEN 1 AND 96),
    ip             TEXT    CHECK (ip IS NULL OR length(ip) BETWEEN 7 AND 15),
    mac            TEXT    CHECK (mac IS NULL OR length(mac) = 17),
    hostname       TEXT    CHECK (hostname IS NULL OR length(hostname) BETWEEN 1 AND 253),
    kind           TEXT    NOT NULL DEFAULT 'unknown' CHECK (kind IN ('firewall', 'router', 'switch', 'ap', 'nas', 'server', 'pc', 'printer', 'camera', 'nvr', 'iot', 'web', 'unknown')),
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
    last_seen      TEXT    NOT NULL CHECK (last_seen GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z')
);
-- One IP, one device (409 duplicate_ip). NULL = no IP known (a manual device whose IP is unknown).
CREATE UNIQUE INDEX inv_asset_ip_uq ON inv_asset (ip) WHERE ip IS NOT NULL;
-- Exactly one box (INV-3).
CREATE UNIQUE INDEX inv_asset_box_uq ON inv_asset (is_box) WHERE is_box = 1;
-- ponytail: not unique (DATA_MODEL says UQ): sensors see the same DHCP hostname on several devices, and a
-- unique index would make RecomputeAsset fail on real LANs. Manual paths check names themselves.
CREATE INDEX inv_asset_hostname_ix ON inv_asset (lower(hostname)) WHERE hostname IS NOT NULL;
CREATE UNIQUE INDEX inv_asset_mac_uq ON inv_asset (mac) WHERE mac IS NOT NULL;
CREATE INDEX inv_asset_kind_ix ON inv_asset (kind);
CREATE INDEX inv_asset_approved_ix ON inv_asset (approved);
CREATE INDEX inv_asset_last_seen_ix ON inv_asset (last_seen);

-- Observation log: append-only (INV-1). The one exception is an exact repeat of (asset, field, source,
-- value), which moves seen_at forward and keeps the higher confidence.
CREATE TABLE inv_observation (
    id         TEXT NOT NULL PRIMARY KEY CHECK (length(id) BETWEEN 1 AND 96),
    asset_id   TEXT NOT NULL REFERENCES inv_asset (id) ON DELETE CASCADE,
    field      TEXT NOT NULL CHECK (field IN ('kind', 'hostname', 'mac', 'vendor', 'model', 'os')),
    value      TEXT NOT NULL CHECK (length(value) BETWEEN 1 AND 253),
    source     TEXT NOT NULL CHECK (source IN ('manual', 'agent', 'snmp', 'nmap', 'passive', 'scan')),
    confidence REAL NOT NULL CHECK (confidence BETWEEN 0 AND 1),
    seen_at    TEXT NOT NULL CHECK (seen_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    evidence   TEXT
);
CREATE UNIQUE INDEX inv_observation_uq ON inv_observation (asset_id, field, source, value);
CREATE INDEX inv_observation_field_ix ON inv_observation (asset_id, field);

-- A value never changes in place: only seen_at and confidence may move.
-- +goose StatementBegin
CREATE TRIGGER inv_observation_append_only BEFORE UPDATE ON inv_observation
WHEN NEW.id IS NOT OLD.id OR NEW.asset_id IS NOT OLD.asset_id OR NEW.field IS NOT OLD.field OR NEW.value IS NOT OLD.value
  OR NEW.source IS NOT OLD.source OR NEW.evidence IS NOT OLD.evidence
BEGIN
    SELECT RAISE(ABORT, 'inv_observation is append-only');
END;
-- +goose StatementEnd

CREATE TABLE inv_service (
    id         TEXT    NOT NULL PRIMARY KEY CHECK (length(id) BETWEEN 1 AND 96),
    asset_id   TEXT    NOT NULL REFERENCES inv_asset (id) ON DELETE CASCADE,
    port       INTEGER NOT NULL CHECK (port BETWEEN 1 AND 65535),
    proto      TEXT    NOT NULL CHECK (proto IN ('tcp', 'udp')),
    name       TEXT    NOT NULL CHECK (length(name) <= 100),
    product    TEXT    CHECK (product IS NULL OR length(product) <= 200),
    version    TEXT    CHECK (version IS NULL OR length(version) <= 100),
    source     TEXT    NOT NULL CHECK (source IN ('manual', 'agent', 'snmp', 'nmap', 'passive', 'scan')),
    confidence REAL    NOT NULL CHECK (confidence BETWEEN 0 AND 1),
    seen_at    TEXT    NOT NULL CHECK (seen_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z')
);
CREATE UNIQUE INDEX inv_service_uq ON inv_service (asset_id, port, proto, source);
CREATE INDEX inv_service_asset_ix ON inv_service (asset_id);

CREATE TABLE inv_software (
    id         TEXT NOT NULL PRIMARY KEY CHECK (length(id) BETWEEN 1 AND 96),
    asset_id   TEXT NOT NULL REFERENCES inv_asset (id) ON DELETE CASCADE,
    display    TEXT NOT NULL CHECK (length(display) BETWEEN 1 AND 200),
    vendor     TEXT NOT NULL CHECK (length(vendor) BETWEEN 1 AND 200),
    product    TEXT NOT NULL CHECK (length(product) BETWEEN 1 AND 200),
    version    TEXT CHECK (version IS NULL OR length(version) BETWEEN 1 AND 100),
    cpe        TEXT CHECK (cpe IS NULL OR length(cpe) <= 500),
    source     TEXT NOT NULL CHECK (source IN ('manual', 'agent', 'snmp', 'nmap', 'passive', 'scan')),
    confidence REAL NOT NULL CHECK (confidence BETWEEN 0 AND 1),
    seen_at    TEXT NOT NULL CHECK (seen_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z')
);
-- The same software from the same source once per version (409 duplicate_software). NULL version counts as "".
CREATE UNIQUE INDEX inv_software_uq ON inv_software (asset_id, lower(vendor), lower(product), ifnull(version, ''), source);
CREATE INDEX inv_software_asset_ix ON inv_software (asset_id);

-- Join table of the KEV matcher: "vendorproject|product" keys, lower-case (S-INV-2).
CREATE TABLE inv_software_kev (
    software_id TEXT NOT NULL REFERENCES inv_software (id) ON DELETE CASCADE,
    kev_key     TEXT NOT NULL CHECK (length(kev_key) BETWEEN 1 AND 400),
    PRIMARY KEY (software_id, kev_key)
);
CREATE INDEX inv_software_kev_ix ON inv_software_kev (kev_key);

-- One key = one configuration object (DATA_MODEL 5.5). Defaults are data, loaded here (DATA_MODEL 6, rule 8).
CREATE TABLE inv_setting (
    key        TEXT NOT NULL PRIMARY KEY CHECK (key IN ('lan_ranges', 'active', 'fragile_kinds', 'regular_scan_kinds', 'scope', 'notify_new')),
    value      TEXT NOT NULL CHECK (json_valid(value)),
    updated_at TEXT NOT NULL CHECK (updated_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    updated_by TEXT NOT NULL CHECK (length(updated_by) BETWEEN 1 AND 320)
);
INSERT INTO inv_setting (key, value, updated_at, updated_by) VALUES
    ('lan_ranges', '[]', strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), 'system'),
    ('active', '{"enabled":false,"days":[1,2,3,4,5,6,7],"from":"23:00","to":"05:00","rate":50,"exclusions":[]}', strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), 'system'),
    ('fragile_kinds', '["printer","camera","nvr","nas","ap","iot"]', strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), 'system'),
    ('regular_scan_kinds', '[]', strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), 'system'),
    ('scope', '{"confirmed_at":null,"confirmed_by":null}', strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), 'system'),
    ('notify_new', '{"enabled":true}', strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), 'system')
ON CONFLICT (key) DO NOTHING;
