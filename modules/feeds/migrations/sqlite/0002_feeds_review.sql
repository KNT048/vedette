-- +goose Up
-- rev counts the edits of a feed (address, rules, kind, switch): a pull that started before an edit sees a
-- different rev when it comes to write and drops its result instead of storing it under the new settings.
ALTER TABLE feeds_source ADD COLUMN rev INTEGER NOT NULL DEFAULT 0 CHECK (rev >= 0);

-- device_added: the "I have it" device of this product was created through the inventory (once per product,
-- whatever the later answers). 0 while the answer was given with the inventory off: the pull job adds it
-- when the inventory becomes available.
ALTER TABLE feeds_weekly_answer ADD COLUMN device_added INTEGER NOT NULL DEFAULT 0 CHECK (device_added IN (0, 1));
