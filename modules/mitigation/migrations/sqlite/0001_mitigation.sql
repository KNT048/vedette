-- +goose Up
-- The whole schema of the mitigation module. It is edited in place until the first public release; docs/SCHEMA.sql
-- shows the schema of every module together. Forward-only: there is no Down section.

-- Items marked "Applied" on a finding (INV-1). One row per item; it never changes the finding's status.
CREATE TABLE mit_applied (
    finding_id TEXT NOT NULL REFERENCES fnd_finding (id) ON DELETE CASCADE,
    item       TEXT NOT NULL CHECK (item IN ('patch', 'workaround', 'fortigate', 'mikrotik', 'generic')),
    ts         TEXT NOT NULL CHECK (ts GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    user       TEXT NOT NULL CHECK (length(user) BETWEEN 1 AND 320),
    PRIMARY KEY (finding_id, item)
) WITHOUT ROWID;

-- Last AI result per finding and skill (INV-3). Living in this table is what marks it "AI generated":
-- it is never mixed with mit_pack.
CREATE TABLE mit_ai_output (
    finding_id  TEXT NOT NULL REFERENCES fnd_finding (id) ON DELETE CASCADE,
    skill       TEXT NOT NULL CHECK (skill IN ('explain', 'mitigation-config')),
    payload     TEXT NOT NULL CHECK (json_valid(payload) AND json_type(payload) = 'object'),
    model       TEXT NOT NULL CHECK (length(model) <= 200),
    profile     TEXT CHECK (profile IS NULL OR length(profile) <= 200),
    created_at  TEXT NOT NULL CHECK (created_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    activity_id TEXT CHECK (activity_id IS NULL OR length(activity_id) BETWEEN 1 AND 96),
    PRIMARY KEY (finding_id, skill)
) WITHOUT ROWID;

-- Confirmed packs loaded from a signed update (INV-2). The whole table is replaced in one transaction
-- on every load; the content itself is a signed file, not customer data.
CREATE TABLE mit_pack (
    cve          TEXT NOT NULL PRIMARY KEY CHECK (cve GLOB 'CVE-[0-9][0-9][0-9][0-9]-[0-9][0-9][0-9][0-9]*'),
    -- patch, workaround, firewall[], checklist, sources[] and the optional recheck block
    body         TEXT NOT NULL CHECK (json_valid(body) AND json_type(body) = 'object'),
    compromise   TEXT CHECK (compromise IS NULL OR (json_valid(compromise) AND json_type(compromise) = 'object')),
    confirmed_by TEXT NOT NULL CHECK (length(confirmed_by) BETWEEN 1 AND 320),
    confirmed_at TEXT NOT NULL CHECK (confirmed_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]*'),
    drafted_with TEXT NOT NULL CHECK (length(drafted_with) BETWEEN 1 AND 200),
    pack_version TEXT NOT NULL CHECK (length(pack_version) BETWEEN 1 AND 64)
) WITHOUT ROWID;

-- The version of the update the loaded packs came from (one row), so an older or repeated update
-- cannot be installed again (replay protection of Loader.Install).
CREATE TABLE mit_pack_state (
    id           INTEGER NOT NULL PRIMARY KEY CHECK (id = 1),
    version      TEXT    NOT NULL CHECK (length(version) BETWEEN 1 AND 64),
    installed_at TEXT    NOT NULL CHECK (installed_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z')
);
