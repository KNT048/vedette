-- +goose Up
-- INV-39 (BN340, n82; review r1 H1 of #950): a person corrects a software row a sensor or agent reported. The correction is a manual
-- row; corrects is the identity of exactly the row it replaces: source, lower(vendor), lower(product) and version, joined by char(31)
-- (the unique index inv_software_uq allows one such row per device). A re-report of that row (the same source, product and version)
-- is replaced too; another install (another version, another source) is not. set_by is the person who set it (the findings history
-- names them, review r1 M3). Only a manual row corrects; NULL for every other row. Forward-only (DATA_MODEL 6, rule 1).
ALTER TABLE inv_software ADD COLUMN corrects TEXT CHECK (corrects IS NULL OR (source = 'manual' AND length(corrects) BETWEEN 4 AND 520));
ALTER TABLE inv_software ADD COLUMN set_by TEXT CHECK (set_by IS NULL OR length(set_by) BETWEEN 1 AND 320);
CREATE INDEX inv_software_corrects_ix ON inv_software (asset_id, corrects) WHERE corrects IS NOT NULL;
