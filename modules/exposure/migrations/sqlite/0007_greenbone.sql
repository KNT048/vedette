-- +goose Up
-- S-EXP-2 (INV-25, D-563): the optional deep scan with Greenbone (OpenVAS), off by default. exp_setting keeps whether an
-- administrator enabled it, who and when; exp_snapshot keeps its results (QoD >= 70) as a JSON array like the other lists of a
-- snapshot. A snapshot taken before this version has none ('[]'). Forward-only (DATA_MODEL 6, rule 1).
ALTER TABLE exp_setting ADD COLUMN greenbone INTEGER NOT NULL DEFAULT 0 CHECK (greenbone IN (0, 1));
ALTER TABLE exp_setting ADD COLUMN greenbone_by TEXT;
ALTER TABLE exp_setting ADD COLUMN greenbone_at TEXT;
ALTER TABLE exp_snapshot ADD COLUMN greenbone TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(greenbone) AND json_type(greenbone) = 'array');
