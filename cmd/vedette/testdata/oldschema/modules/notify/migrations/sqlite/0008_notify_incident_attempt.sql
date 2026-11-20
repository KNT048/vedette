-- +goose Up
-- A bad_address incident whose connection the device that logged it blocked is an attempt (D-227): the list and the detail say
-- "Attempt to reach a known-bad address". An older binary writes 0 (a connection), which is what it said before.
ALTER TABLE notify_incident ADD COLUMN attempt INTEGER NOT NULL DEFAULT 0 CHECK (attempt IN (0, 1));
