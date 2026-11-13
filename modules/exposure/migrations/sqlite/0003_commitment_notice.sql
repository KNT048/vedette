-- +goose Up
-- The commitment of D-26 is now recorded by an administrator's first Scan now (D-473): next to who and when it keeps the version
-- and the exact sentence shown beside the button, so the record says what was agreed to, not only that a box was ticked.
-- Both stay NULL on a commitment recorded before D-473 (a ticked box without a stored sentence) and on a target without one.
-- Forward-only (DATA_MODEL 6, rule 1).
ALTER TABLE exp_target ADD COLUMN commitment_version TEXT CHECK (commitment_version IS NULL OR (length(commitment_version) BETWEEN 1 AND 40 AND commitment_by IS NOT NULL));
ALTER TABLE exp_target ADD COLUMN commitment_sentence TEXT CHECK ((commitment_version IS NULL) = (commitment_sentence IS NULL) AND (commitment_sentence IS NULL OR length(commitment_sentence) BETWEEN 1 AND 1000));
