-- +goose Up
-- The CISA list is pulled every hour (S-FEED-1: Home data at most an hour old, D-485); a pull that finds no change is
-- a 304 answer to If-None-Match/If-Modified-Since. A box that still has the old daily default moves to hourly; a
-- schedule the admin chose (anything but 24) is kept. A new box gets 1 from the seed.
UPDATE feeds_source SET interval_hours = 1 WHERE id = 'cisa-kev' AND builtin = 1 AND interval_hours = 24;
-- The CISA GitHub mirror (D-91) gets its own validators, so an hourly pull while CISA refuses the box is a 304 there too; a box whose
-- last good pull came from the mirror moves the mirror's validators out of etag/last_modified, which are CISA's alone from now on.
ALTER TABLE feeds_source ADD COLUMN mirror_etag TEXT;
ALTER TABLE feeds_source ADD COLUMN mirror_last_modified TEXT;
UPDATE feeds_source SET mirror_etag = etag, mirror_last_modified = last_modified, etag = NULL, last_modified = NULL
WHERE id = 'cisa-kev' AND answered_by = 'CISA GitHub mirror';
