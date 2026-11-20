-- +goose Up
-- The whole schema of the findings module. It is edited in place until the first public release; docs/SCHEMA.sql
-- shows the schema of every module together. Forward-only: there is no Down section.

-- D-500: a software whose product is on the exploited list but whose version is missing or unreadable gets ONE row here
-- ("add the version to check N exploited CVEs") instead of one finding per CVE. Rewritten for the device on every match
-- of it (UpsertFromMatch), removed with the device (OnAssetDeleted, reconcile). Not a finding: no status, no history.
-- asset_id and software_id have no foreign key (inventory owns them, rules/modules.md). Forward-only (DATA_MODEL 6, rule 1).
CREATE TABLE fnd_version_needed (
    asset_id    TEXT    NOT NULL CHECK (length(asset_id) BETWEEN 1 AND 96),
    software_id TEXT    NOT NULL CHECK (length(software_id) BETWEEN 1 AND 96),
    software    TEXT    NOT NULL CHECK (length(software) <= 200),
    version     TEXT    NOT NULL CHECK (length(version) <= 200),
    cves        INTEGER NOT NULL CHECK (cves > 0),
    updated_at  TEXT    NOT NULL CHECK (updated_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    PRIMARY KEY (asset_id, software_id)
);

-- #910 phase 1 (audit): one row per run of the KEV reachability audit, run after a refresh of the exploited list or of NVD's
-- affected versions (cmd/vedette job reach-audit, findings.Reachability): the feed stamp it read, the count of entries per class
-- (1 no NVD data, 2 no NVD versions, 3v keyed with a version, 3k keyed without one, 4 reached through NVD's list, 5 nothing), the
-- CVEs of each class no version comparison can reach (1, 2, 3k, 5) and those not in that class in the previous run (added). A run
-- whose classes equal the previous one's is not stored, whatever the stamp: each row is a change; the newest 30 are kept. Public feed data only, no device data.
-- Forward-only (DATA_MODEL 6, rule 1).
CREATE TABLE fnd_reach_run (
    id          INTEGER PRIMARY KEY,
    ran_at      TEXT    NOT NULL CHECK (ran_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    stamp       TEXT    NOT NULL CHECK (length(stamp) <= 4000),
    total       INTEGER NOT NULL CHECK (total >= 0),
    counts      TEXT    NOT NULL CHECK (json_valid(counts) AND json_type(counts) = 'object'),
    unreachable TEXT    NOT NULL CHECK (json_valid(unreachable) AND json_type(unreachable) = 'object'),
    added       TEXT    NOT NULL CHECK (json_valid(added) AND json_type(added) = 'object')
);

-- D-602 (review r1 H2 of #939): the (device, CVE) pairs the "could not be checked" list has ever held for a device, or that had a
-- finding: a pair new here is announced once (findings.unchecked.added, one event per device and match write, notify sends one
-- notice listing the CVEs), never again. Seeded with every pair the box already listed or had a finding for, so the upgrade itself
-- (old product findings closing into the list) announces nothing. Removed with the device; moved on a merge. No foreign keys
-- (inventory owns the ids, rules/modules.md). Forward-only (DATA_MODEL 6, rule 1).
CREATE TABLE fnd_unchecked_seen (
    asset_id   TEXT NOT NULL CHECK (length(asset_id) BETWEEN 1 AND 96),
    cve        TEXT NOT NULL CHECK (cve GLOB 'CVE-[0-9][0-9][0-9][0-9]-[0-9][0-9][0-9][0-9]*' AND length(cve) <= 32),
    first_seen TEXT NOT NULL CHECK (first_seen GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    PRIMARY KEY (asset_id, cve)
) WITHOUT ROWID;

CREATE TABLE "fnd_unchecked" (
    asset_id    TEXT NOT NULL CHECK (length(asset_id) BETWEEN 1 AND 96),
    software_id TEXT NOT NULL CHECK (length(software_id) BETWEEN 1 AND 128),
    software    TEXT NOT NULL CHECK (length(software) <= 200),
    version     TEXT NOT NULL CHECK (length(version) <= 200),
    source      TEXT NOT NULL CHECK (length(source) <= 32),
    reason      TEXT NOT NULL CHECK (reason IN ('no_nvd_data', 'no_nvd_versions', 'not_named', 'not_comparable', 'platform_unknown', 'package_unknown')),
    cve         TEXT NOT NULL CHECK (cve GLOB 'CVE-[0-9][0-9][0-9][0-9]-[0-9][0-9][0-9][0-9]*' AND length(cve) <= 32),
    updated_at  TEXT NOT NULL CHECK (updated_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    nvd_pending INTEGER NOT NULL DEFAULT 0 CHECK (nvd_pending IN (0, 1)),
    answer      TEXT NOT NULL DEFAULT '' CHECK (length(answer) <= 200), -- package_unknown: the release a person gave that is not one
    PRIMARY KEY (asset_id, software_id, cve)
);

-- INV-6c: the mark a finding was closed for when a person said its software is not installed: the identity of the reported row the
-- mark covers (inventory's row key: source, vendor, product and version). A later match that brings that very row back is the person
-- clearing the mark (no notice); any other row is a new reading (a notice). Removed with the finding. Forward-only (DATA_MODEL 6, rule 1).
CREATE TABLE fnd_not_installed (
    finding_id TEXT NOT NULL PRIMARY KEY REFERENCES fnd_finding (id) ON DELETE CASCADE,
    mark       TEXT NOT NULL CHECK (length(mark) BETWEEN 4 AND 520)
) WITHOUT ROWID;

CREATE TABLE "fnd_finding_history" (
    id         TEXT NOT NULL PRIMARY KEY CHECK (length(id) BETWEEN 1 AND 96),
    finding_id TEXT NOT NULL REFERENCES fnd_finding (id) ON DELETE CASCADE,
    ts         TEXT NOT NULL CHECK (ts GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    user       TEXT NOT NULL CHECK (length(user) BETWEEN 1 AND 320),
    action     TEXT NOT NULL CHECK (action IN ('created', 'confirmed', 'rescanned', 'rescan_clear', 'no_longer_matches', 'matches_again', 'reopened', 'patched', 'mitigated', 'false_positive', 'not_relevant', 'risk_accepted', 'confirm_undone')),
    note       TEXT CHECK (note IS NULL OR length(note) <= 600)
);

-- One time, after a version the device itself reports started to confirm a finding (migration 0014): open findings that become
-- confirmed only because of that rule must not send one notice each. While fnd_device_backfill_pending has its row, the matcher
-- records each such finding in fnd_device_backfill (and its history) instead of publishing a status change; the next full match pass
-- (Reconcile) sends one summary and empties both tables. A box installed with this migration has no such finding: its first pass
-- only removes the marker. Forward-only (DATA_MODEL 6, rule 1).
CREATE TABLE fnd_device_backfill_pending (
    id INTEGER NOT NULL PRIMARY KEY CHECK (id = 1)
);

CREATE TABLE fnd_device_backfill (
    finding_id TEXT NOT NULL PRIMARY KEY REFERENCES fnd_finding (id) ON DELETE CASCADE
) WITHOUT ROWID;

CREATE TABLE "fnd_finding" (
    id                TEXT    NOT NULL PRIMARY KEY CHECK (length(id) BETWEEN 1 AND 96),
    asset_id          TEXT    NOT NULL CHECK (length(asset_id) BETWEEN 1 AND 96),
    cve               TEXT    NOT NULL
        CHECK (cve GLOB 'CVE-[0-9][0-9][0-9][0-9]-[0-9][0-9][0-9][0-9]*'
               AND substr(cve, 5) NOT GLOB '*[^0-9-]*'
               AND cve NOT GLOB 'CVE-[0-9][0-9][0-9][0-9]-*-*'),
    status            TEXT    NOT NULL CHECK (status IN ('confirmed', 'suspected', 'mitigated', 'patched', 'false_positive', 'not_relevant', 'risk_accepted')),
    severity          TEXT    NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
    confidence        REAL    NOT NULL CHECK (confidence >= 0 AND confidence <= 1),
    basis             TEXT    NOT NULL CHECK (basis IN ('scan', 'version', 'product', 'person')),
    evidence          TEXT    CHECK (evidence IS NULL OR (json_valid(evidence) AND json_type(evidence) = 'object')),
    first_seen        TEXT    NOT NULL CHECK (first_seen GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    last_seen         TEXT    NOT NULL CHECK (last_seen GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    resolved_by       TEXT    CHECK (resolved_by IS NULL OR length(resolved_by) BETWEEN 1 AND 320),
    resolved_at       TEXT    CHECK (resolved_at IS NULL OR resolved_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    resolution_note   TEXT    CHECK (resolution_note IS NULL OR length(resolution_note) <= 500),
    resolution_reason TEXT    CHECK (resolution_reason IS NULL OR resolution_reason IN ('not_affected_version', 'fixed_by_update')),
    -- The last day of a risk acceptance (UTC); set exactly while the status is risk_accepted.
    accepted_until    TEXT    CHECK (accepted_until IS NULL OR accepted_until GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]'),
    software_id       TEXT    CHECK (software_id IS NULL OR length(software_id) BETWEEN 1 AND 200),
    proved_version    TEXT    CHECK (proved_version IS NULL OR length(proved_version) BETWEEN 1 AND 200),
    -- confirmed: a scan or a person, or a version the device itself stated (its SNMP answer or its own agent) inside an affected
    -- range with an end: basis version and the evidence's source says so.
    CHECK (status <> 'confirmed' OR (evidence IS NOT NULL AND (basis IN ('scan', 'person')
        OR (basis = 'version' AND coalesce(json_extract(evidence, '$.source'), '') IN ('snmp', 'agent'))))),
    CHECK ((status = 'risk_accepted') = (accepted_until IS NOT NULL)),
    CHECK (coalesce(resolution_reason, '') <> 'fixed_by_update' OR status = 'patched'),
    UNIQUE (asset_id, cve)
);

-- One time, after Vedette started to close a finding whose device moved to a version outside the affected range as patched (migration
-- 0016): findings it closed before as not affected after such a move become patched in the next full match pass (reclassifyPatched),
-- with no notice. The pass drops this marker. A box installed with this migration has no such finding: the first pass only drops it.
-- Forward-only (DATA_MODEL 6, rule 1).
CREATE TABLE fnd_patched_backfill_pending (
    id INTEGER NOT NULL PRIMARY KEY CHECK (id = 1)
);

-- A recommended update ("Updates to plan" item) a person marked as done: hidden from the plan until the device reports another
-- version of that software, or a CVE that was not in the item joins it (findings INV-20). One row per item key (PlanItem.group).
CREATE TABLE fnd_plan_done (
    item_key  TEXT NOT NULL PRIMARY KEY CHECK (length(item_key) BETWEEN 1 AND 400),
    asset_id  TEXT NOT NULL CHECK (length(asset_id) BETWEEN 1 AND 96),
    version   TEXT NOT NULL CHECK (length(version) <= 200),
    cves      TEXT NOT NULL CHECK (json_valid(cves) AND json_type(cves) = 'array'),
    note      TEXT CHECK (note IS NULL OR length(note) <= 500),
    done_by   TEXT NOT NULL CHECK (length(done_by) BETWEEN 1 AND 320),
    done_at   TEXT NOT NULL CHECK (done_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z')
) WITHOUT ROWID;

CREATE INDEX fnd_finding_history_finding_idx ON fnd_finding_history (finding_id, ts);

CREATE INDEX fnd_finding_status_idx ON fnd_finding (status);

CREATE INDEX fnd_finding_cve_idx ON fnd_finding (cve);

CREATE INDEX fnd_finding_asset_status_idx ON fnd_finding (asset_id, status);

-- #825 (INV-23): Home's 30-day trend reads the findings closed inside the window. With the status index alone SQLite visits every
-- closed finding ever and filters resolved_at row by row; (status, resolved_at) makes it a range per closed status. Only an index:
-- no row changes. Forward-only (DATA_MODEL 6, rule 1).
CREATE INDEX fnd_finding_status_resolved_idx ON fnd_finding (status, resolved_at);

CREATE INDEX fnd_plan_done_asset_idx ON fnd_plan_done (asset_id);

INSERT INTO fnd_device_backfill_pending (id) VALUES (1);

INSERT INTO fnd_patched_backfill_pending (id) VALUES (1);

-- +goose StatementBegin
CREATE TRIGGER fnd_finding_history_no_update BEFORE UPDATE ON fnd_finding_history
BEGIN
    SELECT RAISE(ABORT, 'fnd_finding_history is append-only');
END;
-- +goose StatementEnd
