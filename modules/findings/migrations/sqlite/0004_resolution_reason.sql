-- +goose Up
-- D-530: why a finding was closed when Vedette closed it by itself. NULL for every finding a person closed (their note says
-- why) and for open ones; 'not_affected_version' when the matcher proved the device's version is outside every NVD range of
-- the CVE (status not_relevant, resolved_by 'system'). Only such a finding is reopened by a later match (matches_again).
-- Adding a nullable column keeps every existing row as it is. Forward-only (DATA_MODEL 6, rule 1).
ALTER TABLE fnd_finding ADD COLUMN resolution_reason TEXT CHECK (resolution_reason IS NULL OR resolution_reason IN ('not_affected_version'));
