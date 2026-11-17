-- +goose Up
-- The hotpatches of Microsoft's hotpatch calendars (feed windows-releases) beside the monthly updates of feeds_winrel_update: a device
-- enrolled in hotpatching runs a hotpatch revision below the month's B build, with that month's security fixes, so findings reads it
-- as current to its month (core/winrel.Baseline). A hotpatch is never a target. Existing rows are monthly updates. Forward-only.
ALTER TABLE feeds_winrel_update ADD COLUMN hotpatch INTEGER NOT NULL DEFAULT 0 CHECK (hotpatch IN (0, 1));
