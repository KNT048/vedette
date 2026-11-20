-- +goose Up
-- "I have this" means "alert me about this product" (D-484): device_id is the device the answer declared (NULL until the
-- inventory names it), have_since the CISA date its version-less product is matched from on that device only. Both are
-- written by the first "have" and never moved by later answers.
ALTER TABLE feeds_weekly_answer ADD COLUMN device_id TEXT CHECK (device_id IS NULL OR length(device_id) BETWEEN 1 AND 64);
ALTER TABLE feeds_weekly_answer ADD COLUMN have_since TEXT CHECK (have_since IS NULL OR have_since GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]');
