-- +goose Up
-- The whole schema of the findings module. It is edited in place until the first public release; docs/SCHEMA.sql
-- shows the schema of every module together. Forward-only: there is no Down section.

-- One row per (device, CVE, software line) that was affected at some time. Three separate facts, each with one writer:
--   A. detection (detected .. evidence): only the match pass and the safe checks write it;
--   B. handling (state .. to_version): a person, or Vedette when the data no longer detects the flaw;
--   C. urgency (urgency, urgency_at): only the urgency pass writes it.
-- Every change of B goes through findings.Transition, which also appends the fnd_finding_event rows. A pair that was checked and
-- found not affected has no row; a pair Vedette cannot decide without a person is a fnd_question, not a finding.
CREATE TABLE fnd_finding (
    id             TEXT    NOT NULL PRIMARY KEY CHECK (length(id) BETWEEN 1 AND 96),
    asset_id       TEXT    NOT NULL REFERENCES inv_asset (id) ON DELETE CASCADE,
    cve            TEXT    NOT NULL
        CHECK (cve GLOB 'CVE-[0-9][0-9][0-9][0-9]-[0-9][0-9][0-9][0-9]*'
               AND substr(cve, 5) NOT GLOB '*[^0-9-]*'
               AND cve NOT GLOB 'CVE-[0-9][0-9][0-9][0-9]-*-*'),
    -- The software line the CVE is on; NULL only for a safe-check hit on a device with no line for that product.
    software_id    TEXT    REFERENCES inv_software (id) ON DELETE SET NULL,
    -- A. detection
    detected       INTEGER NOT NULL CHECK (detected IN (0, 1)),
    basis          TEXT    NOT NULL CHECK (length(basis) BETWEEN 1 AND 40 AND basis NOT GLOB '*[^a-z0-9_]*'),
    verified       TEXT    NOT NULL CHECK (verified IN ('no', 'device', 'scan', 'person')),
    range_origin   TEXT    NOT NULL CHECK (length(range_origin) BETWEEN 1 AND 40 AND range_origin NOT GLOB '*[^a-z0-9_]*'),
    matched_version TEXT   CHECK (matched_version IS NULL OR length(matched_version) BETWEEN 1 AND 200),
    fix_kind       TEXT    NOT NULL CHECK (length(fix_kind) BETWEEN 1 AND 40 AND fix_kind NOT GLOB '*[^a-z0-9_]*'),
    fix_version    TEXT    CHECK (fix_version IS NULL OR length(fix_version) BETWEEN 1 AND 200),
    fix_ref        TEXT    CHECK (fix_ref IS NULL OR length(fix_ref) BETWEEN 1 AND 200),
    fix_key        TEXT    NOT NULL CHECK (length(fix_key) BETWEEN 1 AND 400),
    evidence       TEXT    CHECK (evidence IS NULL OR (json_valid(evidence) AND json_type(evidence) = 'object')),
    -- B. handling
    state          TEXT    NOT NULL CHECK (state IN ('open', 'handled')),
    resolution     TEXT    CHECK (resolution IS NULL OR resolution IN ('patched', 'mitigated', 'accepted', 'false_positive', 'not_relevant')),
    via            TEXT    CHECK (via IS NULL OR (length(via) BETWEEN 1 AND 40 AND via NOT GLOB '*[^a-z0-9_]*')),
    resolved_by    TEXT    CHECK (resolved_by IS NULL OR length(resolved_by) BETWEEN 1 AND 320),
    resolved_at    TEXT    CHECK (resolved_at IS NULL OR resolved_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    note           TEXT    CHECK (note IS NULL OR length(note) <= 600),
    -- The last day of a risk acceptance (UTC); the finding reopens by itself once that day is over everywhere.
    accepted_until TEXT    CHECK (accepted_until IS NULL OR accepted_until GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]'),
    -- via version_moved: the version that was affected and the version installed now ("6.24 -> 7.23").
    from_version   TEXT    CHECK (from_version IS NULL OR length(from_version) BETWEEN 1 AND 200),
    to_version     TEXT    CHECK (to_version IS NULL OR length(to_version) BETWEEN 1 AND 200),
    -- C. urgency: 1 under attack here, 2 exploited, 3 public exploit, 4 critical on an edge device, 5 update recommended
    urgency        INTEGER NOT NULL CHECK (urgency BETWEEN 1 AND 5),
    urgency_at     TEXT    NOT NULL CHECK (urgency_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    first_seen     TEXT    NOT NULL CHECK (first_seen GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    last_seen      TEXT    NOT NULL CHECK (last_seen GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    updated_at     TEXT    NOT NULL CHECK (updated_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    CHECK ((state = 'open') = (resolution IS NULL)),
    CHECK ((state = 'open') = (via IS NULL)),
    CHECK ((state = 'open') = (resolved_by IS NULL)),
    CHECK ((state = 'open') = (resolved_at IS NULL)),
    CHECK ((resolution IS 'accepted') = (accepted_until IS NOT NULL)),
    CHECK ((via IS 'version_moved') = (from_version IS NOT NULL AND to_version IS NOT NULL AND from_version <> to_version)),
    CHECK (via IS 'version_moved' OR (from_version IS NULL AND to_version IS NULL))
);

CREATE UNIQUE INDEX fnd_finding_line_uq ON fnd_finding (asset_id, cve, ifnull(software_id, ''));

CREATE INDEX fnd_finding_state_urgency_ix ON fnd_finding (state, urgency);

CREATE INDEX fnd_finding_asset_state_ix ON fnd_finding (asset_id, state);

CREATE INDEX fnd_finding_cve_ix ON fnd_finding (cve);

CREATE INDEX fnd_finding_software_ix ON fnd_finding (software_id);

CREATE INDEX fnd_finding_fix_ix ON fnd_finding (fix_key, state);

-- Home's trend and the Handled list read the findings handled inside a period.
CREATE INDEX fnd_finding_resolved_ix ON fnd_finding (state, resolved_at);

-- The history of a finding, append-only: what happened, when, by whom ("system" for Vedette). detail holds the structured facts
-- of the change (resolution, via, versions, layer, why it reopened, the note) for display; no logic reads it.
CREATE TABLE fnd_finding_event (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id TEXT    NOT NULL REFERENCES fnd_finding (id) ON DELETE CASCADE,
    ts         TEXT    NOT NULL CHECK (ts GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    actor      TEXT    NOT NULL CHECK (length(actor) BETWEEN 1 AND 320),
    kind       TEXT    NOT NULL CHECK (length(kind) BETWEEN 1 AND 40 AND kind NOT GLOB '*[^a-z0-9_]*'),
    detail     TEXT    CHECK (detail IS NULL OR (json_valid(detail) AND json_type(detail) = 'object'))
);

CREATE INDEX fnd_finding_event_finding_ix ON fnd_finding_event (finding_id, id);

CREATE INDEX fnd_finding_event_ts_ix ON fnd_finding_event (ts, kind);

-- +goose StatementBegin
CREATE TRIGGER fnd_finding_event_no_update BEFORE UPDATE ON fnd_finding_event
BEGIN
    SELECT RAISE(ABORT, 'fnd_finding_event is append-only');
END;
-- +goose StatementEnd

-- What Vedette cannot decide without a person: a software line with no version it can read, a CVE limited to platforms nothing
-- says the device is on, a distribution's package release it does not know, a version it cannot compare, a CVE with no affected
-- versions. Not a finding. The match pass rewrites a device's questions; an answer stays on its row while the question holds.
CREATE TABLE fnd_question (
    id          TEXT    NOT NULL PRIMARY KEY CHECK (length(id) BETWEEN 1 AND 96),
    asset_id    TEXT    NOT NULL REFERENCES inv_asset (id) ON DELETE CASCADE,
    software_id TEXT    REFERENCES inv_software (id) ON DELETE CASCADE,
    cve         TEXT    CHECK (cve IS NULL OR (cve GLOB 'CVE-[0-9][0-9][0-9][0-9]-[0-9][0-9][0-9][0-9]*' AND length(cve) <= 32)),
    kind        TEXT    NOT NULL CHECK (length(kind) BETWEEN 1 AND 40 AND kind NOT GLOB '*[^a-z0-9_]*'),
    detail      TEXT    CHECK (detail IS NULL OR (json_valid(detail) AND json_type(detail) = 'object')),
    cves        INTEGER NOT NULL CHECK (cves >= 1),
    asked_at    TEXT    NOT NULL CHECK (asked_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    answer      TEXT    CHECK (answer IS NULL OR length(answer) BETWEEN 1 AND 200),
    answered_by TEXT    CHECK (answered_by IS NULL OR length(answered_by) BETWEEN 1 AND 320),
    answered_at TEXT    CHECK (answered_at IS NULL OR answered_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    CHECK ((answer IS NULL) = (answered_by IS NULL) AND (answer IS NULL) = (answered_at IS NULL))
);

CREATE UNIQUE INDEX fnd_question_uq ON fnd_question (asset_id, ifnull(software_id, ''), ifnull(cve, ''), kind);

CREATE INDEX fnd_question_software_ix ON fnd_question (software_id);

-- #910 phase 1 (audit): one row per run of the KEV reachability audit, run after a refresh of the exploited list or of NVD's
-- affected versions (cmd/vedette job reach-audit, findings.Reachability): the feed stamp it read, the count of entries per class
-- (1 no NVD data, 2 no NVD versions, 3v keyed with a version, 3k keyed without one, 4 reached through NVD's list, 5 nothing), the
-- CVEs of each class no version comparison can reach (1, 2, 3k, 5) and those not in that class in the previous run (added). A run
-- whose classes equal the previous one's is not stored, whatever the stamp: each row is a change; the newest 30 are kept. Public feed data only, no device data.
CREATE TABLE fnd_reach_run (
    id          INTEGER PRIMARY KEY,
    ran_at      TEXT    NOT NULL CHECK (ran_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    stamp       TEXT    NOT NULL CHECK (length(stamp) <= 4000),
    total       INTEGER NOT NULL CHECK (total >= 0),
    counts      TEXT    NOT NULL CHECK (json_valid(counts) AND json_type(counts) = 'object'),
    unreachable TEXT    NOT NULL CHECK (json_valid(unreachable) AND json_type(unreachable) = 'object'),
    added       TEXT    NOT NULL CHECK (json_valid(added) AND json_type(added) = 'object')
);
