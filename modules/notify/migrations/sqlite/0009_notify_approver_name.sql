-- +goose Up
-- The shown name of an approver's account on the channel, as the Zalo personal picker gave it (D-447), so the settings dialog names the
-- Zalo account instead of a bare number. Other channels leave it empty; an older binary ignores it.
ALTER TABLE notify_approver ADD COLUMN name TEXT NOT NULL DEFAULT '';
