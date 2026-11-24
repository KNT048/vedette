-- +goose Up
-- Why a request ended when no person decided it and its time did not run out: 'split' (a device split moved its finding to another
-- device and withdrew it). NULL for every other end. The decision answers read it (never the note, which is for people only). The
-- values are checked in Go; there is no CHECK, so an older build can still run on this database after a rollback.
-- Forward-only: there is no Down section.
ALTER TABLE resp_actions ADD COLUMN end_reason TEXT;
