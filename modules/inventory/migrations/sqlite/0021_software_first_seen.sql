-- +goose Up
-- first_seen is when a source first reported a software row (its seen_at is refreshed on every report). A person's correction lapses
-- only for a reading that first appeared after the correction was set and reads a newer release; a reading that was already there is
-- the old one the person overrode. Rows that exist at upgrade have none: they count as read before any correction. Forward-only.
ALTER TABLE inv_software ADD COLUMN first_seen TEXT;
-- The same for operating system readings: an observation's seen_at moves forward on every repeat, first_seen does not. Rows that exist
-- at upgrade have none.
ALTER TABLE inv_observation ADD COLUMN first_seen TEXT;
