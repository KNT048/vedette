-- +goose Up
-- FULL-1 (D-566, kien 2026-11-14): the testing terms of a verified target. One acceptance per target makes every scan of it a deep
-- scan; who accepted, when, the version and the exact text they saw, how they met two-step, and whether they also ticked the
-- disruptive checks (off by default). NULL = not accepted (the old K-4 scope). Forward-only (DATA_MODEL 6, rule 1).
ALTER TABLE exp_target ADD COLUMN terms_version TEXT;
ALTER TABLE exp_target ADD COLUMN terms_by TEXT;
ALTER TABLE exp_target ADD COLUMN terms_at TEXT;
ALTER TABLE exp_target ADD COLUMN terms_text TEXT;
ALTER TABLE exp_target ADD COLUMN terms_user_id TEXT;
ALTER TABLE exp_target ADD COLUMN terms_method TEXT;
ALTER TABLE exp_target ADD COLUMN terms_disruptive INTEGER NOT NULL DEFAULT 0 CHECK (terms_disruptive IN (0, 1));
