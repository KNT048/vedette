-- +goose Up
-- S-EXP-2 (INV-19, D-553): what service identification (nmap -sV) read on the open ports of the box's own public IP, and the
-- lines of what the scan checked and did not check, as JSON arrays like the other lists of a snapshot. A snapshot taken before
-- this version has none of them ('[]'). The exploited CVEs are not stored: they are computed on read from the services and the
-- current KEV list (INV-20). Forward-only (DATA_MODEL 6, rule 1).
ALTER TABLE exp_snapshot ADD COLUMN services TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(services) AND json_type(services) = 'array');
ALTER TABLE exp_snapshot ADD COLUMN checks TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(checks) AND json_type(checks) = 'array');
ALTER TABLE exp_snapshot ADD COLUMN not_checked TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(not_checked) AND json_type(not_checked) = 'array');
