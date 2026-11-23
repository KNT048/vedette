-- +goose Up
-- The whole schema of the inventory module. It is edited in place until the first public release; docs/SCHEMA.sql
-- shows the schema of every module together. Forward-only: there is no Down section.

CREATE TABLE inv_observation (
    id         TEXT NOT NULL PRIMARY KEY CHECK (length(id) BETWEEN 1 AND 96),
    asset_id   TEXT NOT NULL REFERENCES inv_asset (id) ON DELETE CASCADE,
    field      TEXT NOT NULL CHECK (field IN ('kind', 'hostname', 'mac', 'vendor', 'model', 'os')),
    value      TEXT NOT NULL CHECK (length(value) BETWEEN 1 AND 253),
    source     TEXT NOT NULL CHECK (source IN ('manual', 'declared', 'agent', 'snmp', 'nmap', 'passive', 'scan')),
    confidence REAL NOT NULL CHECK (confidence BETWEEN 0 AND 1),
    seen_at    TEXT NOT NULL CHECK (seen_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    evidence   TEXT
, first_seen TEXT);

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
, detail TEXT CHECK (detail IS NULL OR length(detail) <= 200),
    -- when the source last read the port's name, product and version (a scan with version detection, an agent's report); NULL: only
    -- found open. A scan that only finds open ports leaves it; the weekly version read picks the ports read longest ago by it.
    read_at TEXT CHECK (read_at IS NULL OR read_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    -- the address a network scan found the port on: '' for the device's main address (inv_asset.ip) and for sources that read the
    -- whole machine (an agent), else the id of one of its other addresses (inv_asset_address). A scan of one address replaces only
    -- the ports it found there, so two interfaces of one device never replace each other's ports.
    addr_id TEXT NOT NULL DEFAULT '' CHECK (length(addr_id) <= 96));

-- One row per installed software line of a device: one product (core/productid), or one release train of a product whose trains
-- install side by side (line '8' and line '21' of Java). What the sources read are its readings (inv_software_reading); the
-- columns from cpe to seen_at are the effective reading, written only by the resolver in the same transaction as any reading
-- change. The id never changes: a version move updates this row, a removal is a state.
CREATE TABLE inv_software (
    id               TEXT NOT NULL PRIMARY KEY CHECK (length(id) BETWEEN 1 AND 96),
    asset_id         TEXT NOT NULL REFERENCES inv_asset (id) ON DELETE CASCADE,
    product_key      TEXT NOT NULL CHECK (length(product_key) BETWEEN 1 AND 400),
    line             TEXT NOT NULL DEFAULT '' CHECK (length(line) <= 20),
    display          TEXT NOT NULL CHECK (length(display) BETWEEN 1 AND 200),
    vendor           TEXT NOT NULL CHECK (length(vendor) BETWEEN 1 AND 200),
    product          TEXT NOT NULL CHECK (length(product) BETWEEN 1 AND 200),
    cpe              TEXT CHECK (cpe IS NULL OR length(cpe) <= 500),
    version          TEXT CHECK (version IS NULL OR length(version) BETWEEN 1 AND 100),
    pkg_version      TEXT CHECK (pkg_version IS NULL OR length(pkg_version) BETWEEN 1 AND 100),
    pkg_source       TEXT CHECK (pkg_source IS NULL OR length(pkg_source) BETWEEN 1 AND 100),
    packaged         INTEGER NOT NULL DEFAULT 0 CHECK (packaged IN (0, 1)),
    source           TEXT NOT NULL CHECK (length(source) BETWEEN 1 AND 40 AND source NOT GLOB '*[^a-z0-9_]*'),
    set_by           TEXT CHECK (set_by IS NULL OR length(set_by) BETWEEN 1 AND 320),
    confidence       REAL NOT NULL CHECK (confidence BETWEEN 0 AND 1),
    seen_at          TEXT NOT NULL CHECK (seen_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    differs          INTEGER NOT NULL DEFAULT 0 CHECK (differs IN (0, 1)),
    state            TEXT NOT NULL DEFAULT 'present' CHECK (state IN ('present', 'not_installed', 'removed')),
    not_installed_by TEXT CHECK (not_installed_by IS NULL OR length(not_installed_by) BETWEEN 1 AND 320),
    not_installed_at TEXT CHECK (not_installed_at IS NULL OR not_installed_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    first_seen       TEXT NOT NULL CHECK (first_seen GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    last_seen        TEXT NOT NULL CHECK (last_seen GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    removed_at       TEXT CHECK (removed_at IS NULL OR removed_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    CHECK ((state = 'removed') = (removed_at IS NOT NULL)),
    CHECK (state <> 'not_installed' OR not_installed_at IS NOT NULL) -- a removed line keeps a person's mark: it holds when the software is read again
);

-- What each source reads now of a software line: one row per source and the source's own discriminator (instance: '' or a
-- package name, a port, 'os_guess' for nmap's OS fingerprint, 'os' for the OS a network device states). A list replaces the
-- readings of its source (or only the instances its scope covers). first_seen is when the source first read this release. A
-- person's entry is the reading of source 'manual'.
CREATE TABLE inv_software_reading (
    software_id TEXT NOT NULL REFERENCES inv_software (id) ON DELETE CASCADE,
    source      TEXT NOT NULL CHECK (length(source) BETWEEN 1 AND 40 AND source NOT GLOB '*[^a-z0-9_]*'),
    instance    TEXT NOT NULL DEFAULT '' CHECK (length(instance) <= 120),
    display     TEXT NOT NULL CHECK (length(display) BETWEEN 1 AND 200),
    version     TEXT CHECK (version IS NULL OR length(version) BETWEEN 1 AND 100),
    pkg_version TEXT CHECK (pkg_version IS NULL OR length(pkg_version) BETWEEN 1 AND 100),
    pkg_source  TEXT CHECK (pkg_source IS NULL OR length(pkg_source) BETWEEN 1 AND 100),
    packaged    INTEGER NOT NULL DEFAULT 0 CHECK (packaged IN (0, 1)),
    cpe         TEXT CHECK (cpe IS NULL OR length(cpe) <= 500),
    confidence  REAL NOT NULL CHECK (confidence BETWEEN 0 AND 1),
    set_by      TEXT CHECK (set_by IS NULL OR (source = 'manual' AND length(set_by) BETWEEN 1 AND 320)),
    first_seen  TEXT NOT NULL CHECK (first_seen GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    seen_at     TEXT NOT NULL CHECK (seen_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    -- the address a network scan read it at: '' for the device's main address and for sources that read the whole machine, else the
    -- id of one of the device's other addresses (inv_asset_address), as inv_service.addr_id
    addr_id     TEXT NOT NULL DEFAULT '' CHECK (length(addr_id) <= 96),
    PRIMARY KEY (software_id, source, instance, addr_id)
) WITHOUT ROWID;

-- The history of a software line on a device, append-only. The text copies keep a row readable after its line is pruned.
CREATE TABLE inv_software_event (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    asset_id     TEXT NOT NULL CHECK (length(asset_id) BETWEEN 1 AND 96),
    software_id  TEXT NOT NULL CHECK (length(software_id) BETWEEN 1 AND 96),
    product_key  TEXT NOT NULL CHECK (length(product_key) BETWEEN 1 AND 400),
    display      TEXT NOT NULL CHECK (length(display) BETWEEN 1 AND 200),
    ts           TEXT NOT NULL CHECK (ts GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    kind         TEXT NOT NULL CHECK (length(kind) BETWEEN 1 AND 40 AND kind NOT GLOB '*[^a-z0-9_]*'),
    from_version TEXT CHECK (from_version IS NULL OR length(from_version) <= 100),
    to_version   TEXT CHECK (to_version IS NULL OR length(to_version) <= 100),
    source       TEXT CHECK (source IS NULL OR length(source) BETWEEN 1 AND 40),
    actor        TEXT CHECK (actor IS NULL OR length(actor) BETWEEN 1 AND 320)
);

-- One key = one configuration object (DATA_MODEL 5.5). Defaults are data, loaded here (DATA_MODEL 6, rule 8).
CREATE TABLE inv_setting (
    key        TEXT NOT NULL PRIMARY KEY CHECK (key IN ('lan_ranges', 'active', 'fragile_kinds', 'regular_scan_kinds', 'scope', 'notify_new')),
    value      TEXT NOT NULL CHECK (json_valid(value)),
    updated_at TEXT NOT NULL CHECK (updated_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    updated_by TEXT NOT NULL CHECK (length(updated_by) BETWEEN 1 AND 320)
);

CREATE TABLE "inv_asset" (
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
, agent_key TEXT CHECK (agent_key IS NULL OR length(agent_key) BETWEEN 3 AND 81), agent_ip TEXT CHECK (agent_ip IS NULL OR length(agent_ip) BETWEEN 7 AND 15), ip_confirmed_at TEXT, user_name TEXT CHECK (user_name IS NULL OR length(user_name) BETWEEN 1 AND 64), scan_source TEXT CHECK (scan_source IN ('on', 'off')), snmp_source TEXT CHECK (snmp_source IN ('on', 'off')), agent_source TEXT CHECK (agent_source IN ('on', 'off')), ignored_at TEXT, review_earned_at TEXT);

-- The addresses a device answers on besides its main one: the interfaces of a firewall, router or server, a laptop's Wi-Fi and
-- Ethernet. The main address stays on inv_asset (ip, mac), where every identity rule reads it; an address is held in exactly one place
-- (the main columns of one device or one row here), which inventory's writers keep (claimIP, resolve) and a test checks. One row is one
-- interface as it was seen: an IPv4 address, a MAC, or both. The resolver finds a device by any of its addresses. source is what last
-- tied the address to the device: the sensor that last saw it there (passive, nmap, scan, agent, snmp) or merge (a person's merge
-- brought it and nothing has seen it since). A person's split moves a row to a device of its own. Forward-only (DATA_MODEL 6).
CREATE TABLE inv_asset_address (
    id         TEXT NOT NULL PRIMARY KEY CHECK (length(id) BETWEEN 1 AND 96),
    asset_id   TEXT NOT NULL REFERENCES inv_asset (id) ON DELETE CASCADE,
    ip         TEXT CHECK (ip IS NULL OR length(ip) BETWEEN 7 AND 15),
    mac        TEXT CHECK (mac IS NULL OR length(mac) = 17),
    source     TEXT NOT NULL CHECK (length(source) BETWEEN 1 AND 40 AND source NOT GLOB '*[^a-z0-9_]*'),
    first_seen TEXT NOT NULL CHECK (first_seen GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    last_seen  TEXT NOT NULL CHECK (last_seen GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    CHECK (ip IS NOT NULL OR mac IS NOT NULL)
);

-- When each source first reported to this box, so inventory.asset.discovered can say a device was found while the
-- source that found it was still learning the network (its first 36 hours). One row per source (agent, snmp, nmap, passive, scan;
-- never manual), written once by the first observation, software or service list of that source; it only moves back to now when it
-- was stored while the box clock was ahead. The box's own data (EnsureBox, its dpkg list) is no source's contact.
CREATE TABLE inv_source (
    source     TEXT NOT NULL PRIMARY KEY CHECK (source IN ('agent', 'snmp', 'nmap', 'passive', 'scan')),
    first_seen TEXT NOT NULL CHECK (first_seen GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z')
);

-- Two devices a person said are two machines ("Keep separate"): the pair is never offered as "possibly the same device" again.
-- One row per pair, the smaller id first. Deleting either device (by hand, or a join or merge that took it into another) drops the
-- row: a different pair is a new question. Forward-only (DATA_MODEL 6).
CREATE TABLE inv_separate (
    a          TEXT NOT NULL REFERENCES inv_asset (id) ON DELETE CASCADE,
    b          TEXT NOT NULL REFERENCES inv_asset (id) ON DELETE CASCADE,
    decided_by TEXT NOT NULL CHECK (length(decided_by) BETWEEN 1 AND 320),
    decided_at TEXT NOT NULL CHECK (decided_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    PRIMARY KEY (a, b),
    CHECK (a < b)
);

-- A device added by hand with its address only binds the MAC a sensor sees at that address only when that MAC is
-- the first and only one seen there since the person added it. Each MAC seen at the address of such a device (no MAC, no agent) is
-- kept here, by any source: a second MAC means the address is not the person's machine alone (DHCP gave it to another one), so a later
-- machine there is a new, announced device, offered as "possibly the same device" instead of silently inheriting the row.
-- Deleting the device drops its rows. Forward-only (DATA_MODEL 6).
CREATE TABLE inv_hand_seen (
    asset_id   TEXT NOT NULL REFERENCES inv_asset (id) ON DELETE CASCADE,
    mac        TEXT NOT NULL CHECK (length(mac) = 17),
    first_seen TEXT NOT NULL CHECK (first_seen GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    last_seen  TEXT NOT NULL CHECK (last_seen GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    PRIMARY KEY (asset_id, mac)
);

-- INV-47: a person looked at a detected value that differs from what they entered and chose to keep their own. One row per device,
-- field and detected value: the notice stays hidden while the sources keep reading that value, and shows again when they read
-- another. Forward-only (DATA_MODEL 6, rule 1).
CREATE TABLE inv_detected_keep (
    asset_id TEXT NOT NULL REFERENCES inv_asset (id) ON DELETE CASCADE,
    field    TEXT NOT NULL CHECK (field IN ('hostname', 'vendor', 'model', 'os', 'kind')),
    detected TEXT NOT NULL CHECK (length(detected) BETWEEN 1 AND 253),
    kept_at  TEXT NOT NULL,
    kept_by  TEXT,
    PRIMARY KEY (asset_id, field, detected)
) WITHOUT ROWID;

CREATE UNIQUE INDEX inv_observation_uq ON inv_observation (asset_id, field, source, value);

CREATE INDEX inv_observation_field_ix ON inv_observation (asset_id, field);

CREATE UNIQUE INDEX inv_service_uq ON inv_service (asset_id, port, proto, source, addr_id);

CREATE INDEX inv_service_asset_ix ON inv_service (asset_id);

CREATE UNIQUE INDEX inv_software_line_uq ON inv_software (asset_id, product_key, line);

CREATE INDEX inv_software_state_ix ON inv_software (asset_id, state);

CREATE INDEX inv_software_product_ix ON inv_software (product_key);

CREATE INDEX inv_software_event_asset_ix ON inv_software_event (asset_id, ts);

CREATE INDEX inv_software_event_line_ix ON inv_software_event (software_id, ts);

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

CREATE UNIQUE INDEX inv_asset_agent_key ON inv_asset (agent_key) WHERE agent_key IS NOT NULL;

-- The Devices page reads which sources reported each device: the sources of the readings of its software lines.
CREATE INDEX inv_software_reading_source_ix ON inv_software_reading (source, software_id);

-- Every device a batch touched looks for the one other row a sensor saw last with the same private MAC (sameMAC,
-- macHolders). That reads mac observations by value across devices; inv_observation_uq starts with asset_id, so without this index each
-- lookup reads the whole table. Forward-only (DATA_MODEL 6).
CREATE INDEX inv_observation_mac_ix ON inv_observation (value) WHERE field = 'mac';

CREATE INDEX inv_separate_b_ix ON inv_separate (b);

CREATE INDEX inv_hand_seen_mac_ix ON inv_hand_seen (mac);

-- One address, one device: an IP or a MAC is in one row at most (and never also a device's main address, inventory's writers).
CREATE UNIQUE INDEX inv_asset_address_ip_uq ON inv_asset_address (ip) WHERE ip IS NOT NULL;

CREATE UNIQUE INDEX inv_asset_address_mac_uq ON inv_asset_address (mac) WHERE mac IS NOT NULL;

CREATE INDEX inv_asset_address_asset_ix ON inv_asset_address (asset_id);

INSERT INTO inv_setting (key, value, updated_at, updated_by) VALUES ('lan_ranges', '[]', strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), 'system');
INSERT INTO inv_setting (key, value, updated_at, updated_by) VALUES ('active', '{"enabled":false,"days":[1,2,3,4,5,6,7],"from":"22:00","to":"05:00","rate":50,"exclusions":[]}', strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), 'system');
INSERT INTO inv_setting (key, value, updated_at, updated_by) VALUES ('fragile_kinds', '["printer","camera","nvr","nas","ap","iot"]', strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), 'system');
INSERT INTO inv_setting (key, value, updated_at, updated_by) VALUES ('regular_scan_kinds', '[]', strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), 'system');
INSERT INTO inv_setting (key, value, updated_at, updated_by) VALUES ('scope', '{"confirmed_at":null,"confirmed_by":null}', strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), 'system');
INSERT INTO inv_setting (key, value, updated_at, updated_by) VALUES ('notify_new', '{"enabled":true}', strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), 'system');

-- +goose StatementBegin
CREATE TRIGGER inv_observation_append_only BEFORE UPDATE ON inv_observation
WHEN NEW.id IS NOT OLD.id OR NEW.asset_id IS NOT OLD.asset_id OR NEW.field IS NOT OLD.field OR NEW.value IS NOT OLD.value
  OR NEW.source IS NOT OLD.source OR NEW.evidence IS NOT OLD.evidence
BEGIN
    SELECT RAISE(ABORT, 'inv_observation is append-only');
END;
-- +goose StatementEnd

-- +goose StatementBegin
-- History is append-only. The one change allowed is a merge of two rows of one machine (joinAs, foldSoftware): the history follows the
-- device and the software line that stay, so only asset_id and software_id may change.
CREATE TRIGGER inv_software_event_append_only BEFORE UPDATE ON inv_software_event
WHEN NEW.id IS NOT OLD.id OR NEW.product_key IS NOT OLD.product_key OR NEW.display IS NOT OLD.display OR NEW.ts IS NOT OLD.ts
  OR NEW.kind IS NOT OLD.kind OR NEW.from_version IS NOT OLD.from_version OR NEW.to_version IS NOT OLD.to_version
  OR NEW.source IS NOT OLD.source OR NEW.actor IS NOT OLD.actor
BEGIN
    SELECT RAISE(ABORT, 'inv_software_event is append-only');
END;
-- +goose StatementEnd
