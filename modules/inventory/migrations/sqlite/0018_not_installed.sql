-- +goose Up
-- INV-41 (6) (J3, kien G15): a person says a software row a sensor or agent reported is not installed on the device. It is a kind of
-- correction (a manual row with corrects set, the same liveness: in use only while the row it corrects is still reported), so the
-- row it replaces stops matching and the correction itself never matches. 0 for every other row. Forward-only (DATA_MODEL 6, rule 1).
ALTER TABLE inv_software ADD COLUMN not_installed INTEGER NOT NULL DEFAULT 0 CHECK (not_installed IN (0, 1) AND (not_installed = 0 OR corrects IS NOT NULL));
