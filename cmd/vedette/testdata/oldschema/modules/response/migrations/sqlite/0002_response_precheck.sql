-- +goose Up
-- WP-13b slice 13b-2 (D-95): check before and read-back as data. The check before is a read-only template (same shape as run, rollback
-- and verify) and up to 5 texts that make it refuse; the read-back text (`expect`) lives inside the verify JSON, so it needs no column.
-- An older row keeps '{}' and '[]' (no check). Forward-only (DATA_MODEL 6, rule 1).
ALTER TABLE resp_catalog ADD COLUMN precheck TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(precheck));
ALTER TABLE resp_catalog ADD COLUMN precheck_refuse TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(precheck_refuse) AND json_type(precheck_refuse) = 'array');
-- The text the output of the check must contain (D-95 (1), amended 2026-11-10 after the review of 13b-2): the positive counterpart of the refusal texts.
ALTER TABLE resp_catalog ADD COLUMN precheck_expect TEXT NOT NULL DEFAULT '' CHECK (length(precheck_expect) <= 80);
