-- +goose Up
-- D-550: Vedette closes an incident by itself when its cause is gone (a device approved or deleted in Devices, no new activity for a
-- quiet window) and says why in resolved_reason, plain English shown on the list and the detail (INV-22); a person's action clears it.
-- first_run (INV-23): 1 = a low or medium bad-connection or log incident opened in the box's first 36 hours, held for the hourly
-- first-run summary message instead of its own; 2 = told in that summary. An older binary writes 0 (sent one by one, as before).
ALTER TABLE notify_incident ADD COLUMN resolved_reason TEXT CHECK (resolved_reason IS NULL OR length(resolved_reason) <= 500);
ALTER TABLE notify_incident ADD COLUMN first_run INTEGER NOT NULL DEFAULT 0 CHECK (first_run IN (0, 1, 2));
