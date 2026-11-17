-- +goose Up
-- INV-40 (BN340, n82; review r1 H1, r2 M-A of #950): a person corrects a software row a sensor or agent reported. The correction is a
-- manual row; corrects is the identity of exactly the row it replaces: source, lower(vendor), lower(product) and version, joined by
-- char(31) (inv_software_uq allows one such reported row per device). A re-report of that row (the same source, product and version)
-- is replaced too; another install (another version, another source) is not. set_by is the person who set it (the findings history
-- names them, review r1 M3). Only a manual row corrects; NULL for every other row.
-- A reported row has at most one correction (inv_software_corrects_uq). Corrections are left out of inv_software_uq: two sources that
-- read the product wrong are each corrected, maybe to the same version, and a correction never collides with the row it corrects or a
-- row a person declared (review r2 M-A). Forward-only (DATA_MODEL 6, rule 1).
ALTER TABLE inv_software ADD COLUMN corrects TEXT CHECK (corrects IS NULL OR (source = 'manual' AND length(corrects) BETWEEN 4 AND 520));
ALTER TABLE inv_software ADD COLUMN set_by TEXT CHECK (set_by IS NULL OR length(set_by) BETWEEN 1 AND 320);
DROP INDEX inv_software_uq;
CREATE UNIQUE INDEX inv_software_uq ON inv_software (asset_id, lower(vendor), lower(product), ifnull(version, ''), source) WHERE corrects IS NULL;
CREATE UNIQUE INDEX inv_software_corrects_uq ON inv_software (asset_id, corrects) WHERE corrects IS NOT NULL;
