-- +goose Up
-- How far the rescan job has read feeds' record of announced KEV entries (S4b, D-144: the bus is best-effort, so scan
-- catches up on the feeds.vuln.new_kev events it missed). The (time, CVE) of the last entry read; NULL: none yet,
-- start from the first announcement. Forward-only (DATA_MODEL 6, rule 1).
ALTER TABLE scan_setting ADD COLUMN kev_read_at TEXT CHECK (kev_read_at IS NULL OR kev_read_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z');
ALTER TABLE scan_setting ADD COLUMN kev_read_cve TEXT NOT NULL DEFAULT '' CHECK (length(kev_read_cve) <= 64);
