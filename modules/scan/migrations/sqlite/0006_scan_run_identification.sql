-- +goose Up
-- Per device of a Scan now run: what the identification recorded, or why it could not (contract.ts RunIdentRow[], D-501).
-- Older runs and runs that do not identify (schedule, new_kev) keep '[]'. Forward-only (DATA_MODEL 6, rule 1).
ALTER TABLE scan_run ADD COLUMN identification TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(identification) AND json_type(identification) = 'array');
