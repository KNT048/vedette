-- +goose Up
-- kev_announced_at: when feeds announced a CISA KEV entry as new (feeds.vuln.new_kev, POST-1), written in the
-- transaction of the pull. The bus is best-effort (D-144), so a subscriber that missed the event (module off, process
-- down) reads these with Store.NewKEVSince. NULL: never announced (the baseline pull of D-78, a custom feed's CVE, or
-- a row from before this migration).
ALTER TABLE feeds_vuln ADD COLUMN kev_announced_at TEXT CHECK (kev_announced_at IS NULL OR kev_announced_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z');
CREATE INDEX feeds_vuln_kev_announced ON feeds_vuln (kev_announced_at, cve) WHERE kev_announced_at IS NOT NULL;
