-- +goose Up
-- D-564 G6: the weekly update of Greenbone's feed while it is enabled. exp_setting keeps when the last one was tried, whether it
-- worked and what happened, shown on the setting with the next one. None before the first ('NULL'). Forward-only (DATA_MODEL 6, rule 1).
ALTER TABLE exp_setting ADD COLUMN greenbone_sync_at TEXT;
ALTER TABLE exp_setting ADD COLUMN greenbone_sync_ok INTEGER CHECK (greenbone_sync_ok IN (0, 1));
ALTER TABLE exp_setting ADD COLUMN greenbone_sync_note TEXT;
