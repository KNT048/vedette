-- +goose Up
-- The CISA list is pulled every hour (S-FEED-1: Home data at most an hour old, D-485); a pull that finds no change is
-- a 304 answer to If-None-Match/If-Modified-Since. A box that still has the old daily default moves to hourly; a
-- schedule the admin chose (anything but 24) is kept. A new box gets 1 from the seed.
UPDATE feeds_source SET interval_hours = 1 WHERE id = 'cisa-kev' AND builtin = 1 AND interval_hours = 24;
