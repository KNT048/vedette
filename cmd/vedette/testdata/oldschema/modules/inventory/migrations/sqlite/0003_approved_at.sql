-- +goose Up
-- D-471 (beta item 11): when a device was approved, so a person finds again a device they just approved (Devices → All
-- devices → "Approved in the last 24 h"). Set when a person approves a discovered device or when osquery enrolment approves
-- it (INV-25). NULL: not approved, added by hand (approved when it was made), or approved before this column existed.
-- Forward-only (DATA_MODEL 6, rule 1).
ALTER TABLE inv_asset ADD COLUMN approved_at TEXT CHECK (approved_at IS NULL OR approved_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z');
