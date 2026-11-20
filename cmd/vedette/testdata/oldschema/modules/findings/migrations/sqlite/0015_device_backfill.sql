-- +goose Up
-- One time, after a version the device itself reports started to confirm a finding (migration 0014): open findings that become
-- confirmed only because of that rule must not send one notice each. While fnd_device_backfill_pending has its row, the matcher
-- records each such finding in fnd_device_backfill (and its history) instead of publishing a status change; the next full match pass
-- (Reconcile) sends one summary and empties both tables. A box installed with this migration has no such finding: its first pass
-- only removes the marker. Forward-only (DATA_MODEL 6, rule 1).
CREATE TABLE fnd_device_backfill_pending (
    id INTEGER NOT NULL PRIMARY KEY CHECK (id = 1)
);
INSERT INTO fnd_device_backfill_pending (id) VALUES (1);

CREATE TABLE fnd_device_backfill (
    finding_id TEXT NOT NULL PRIMARY KEY REFERENCES fnd_finding (id) ON DELETE CASCADE
) WITHOUT ROWID;
