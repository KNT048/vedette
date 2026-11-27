-- +goose Up
-- Why Debian publishes no security update for an entry it lists as affected ("affected, no fix yet", status open): postponed (a
-- later point release fixes it), ignored, minor (no security advisory), unimportant, end_of_life; '' when an update is expected or
-- the row is not open. Kept for the CVEs of the CISA list, so a finding says why no fixed package comes. Validated in Go
-- (feeds.DistroReasons); no CHECK on an added column, which would make the release unsafe to roll back. Forward-only.
ALTER TABLE feeds_distro_fix ADD COLUMN reason TEXT NOT NULL DEFAULT '';
