-- +goose Up
-- One time, after Vedette started to close a finding whose device moved to a version outside the affected range as patched (migration
-- 0016): findings it closed before as not affected after such a move become patched in the next full match pass (reclassifyPatched),
-- with no notice. The pass drops this marker. A box installed with this migration has no such finding: the first pass only drops it.
-- Forward-only (DATA_MODEL 6, rule 1).
CREATE TABLE fnd_patched_backfill_pending (
    id INTEGER NOT NULL PRIMARY KEY CHECK (id = 1)
);
INSERT INTO fnd_patched_backfill_pending (id) VALUES (1);

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
CREATE INDEX fnd_plan_done_asset_idx ON fnd_plan_done (asset_id);
