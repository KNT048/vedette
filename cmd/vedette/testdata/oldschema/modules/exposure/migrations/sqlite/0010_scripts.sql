-- +goose Up
-- FULL-4 (Trưởng), for Mlee (D-526): the NSE script results of a deep scan (nmap's default, safe and vuln scripts on every open TCP
-- port of a target whose testing terms are accepted), as a JSON array like the other lists of a snapshot. A snapshot that is not
-- of a deep scan, or taken before this version, has none ('[]'). Forward-only (DATA_MODEL 6, rule 1).
ALTER TABLE exp_snapshot ADD COLUMN scripts TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(scripts) AND json_type(scripts) = 'array');
