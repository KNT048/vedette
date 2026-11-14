-- +goose Up
-- S-EXP-2 (INV-24, D-562): the alerts of the passive web scan (ZAP baseline) of a scan, as a JSON array like the other lists of a
-- snapshot. A snapshot taken before this version has none ('[]'). Forward-only (DATA_MODEL 6, rule 1).
ALTER TABLE exp_snapshot ADD COLUMN web_findings TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(web_findings) AND json_type(web_findings) = 'array');
