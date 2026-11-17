-- +goose Up
-- INV-6c: the mark a finding was closed for when a person said its software is not installed: the identity of the reported row the
-- mark covers (inventory's row key: source, vendor, product and version). A later match that brings that very row back is the person
-- clearing the mark (no notice); any other row is a new reading (a notice). Removed with the finding. Forward-only (DATA_MODEL 6, rule 1).
CREATE TABLE fnd_not_installed (
    finding_id TEXT NOT NULL PRIMARY KEY REFERENCES fnd_finding (id) ON DELETE CASCADE,
    mark       TEXT NOT NULL CHECK (length(mark) BETWEEN 4 AND 520)
) WITHOUT ROWID;
