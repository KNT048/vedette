-- +goose Up
-- WP-13b slice 13b-2 (D-95): check before and read-back as data. The check before is a read-only template (same shape as run, rollback
-- and verify) and up to 5 texts that make it refuse; the read-back text (`expect`) lives inside the verify JSON, so it needs no column.
-- An older row keeps '{}' and '[]' (no check). Forward-only (DATA_MODEL 6, rule 1).
ALTER TABLE resp_catalog ADD COLUMN precheck TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(precheck));
ALTER TABLE resp_catalog ADD COLUMN precheck_refuse TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(precheck_refuse) AND json_type(precheck_refuse) = 'array');
