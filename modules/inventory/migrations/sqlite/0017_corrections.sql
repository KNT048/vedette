-- +goose Up
-- INV-39 (BN340, n82): a person corrects a software row a sensor or agent reported. The correction is a manual row; corrects holds the
-- product it replaces, lower(vendor) || '|' || lower(product) of the reported row, so the scan's next row of that product (a new id
-- each time a list is replaced) is replaced too while the correction stands. Only a manual row corrects. NULL for every other row.
-- Forward-only (DATA_MODEL 6, rule 1).
ALTER TABLE inv_software ADD COLUMN corrects TEXT CHECK (corrects IS NULL OR (source = 'manual' AND length(corrects) BETWEEN 3 AND 401));
CREATE INDEX inv_software_corrects_ix ON inv_software (asset_id, corrects) WHERE corrects IS NOT NULL;
