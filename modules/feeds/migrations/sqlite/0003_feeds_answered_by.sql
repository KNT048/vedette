-- +goose Up
-- answered_by: which address answered the last good pull of the CISA list ("CISA" or "CISA GitHub mirror", D-91).
-- NULL for every other feed and before the first good pull.
ALTER TABLE feeds_source ADD COLUMN answered_by TEXT;
