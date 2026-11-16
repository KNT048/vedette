-- +goose Up
-- D-599: two devices a person said are two machines ("Keep separate"): the pair is never offered as "possibly the same device" again.
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
CREATE INDEX inv_separate_b_ix ON inv_separate (b);
