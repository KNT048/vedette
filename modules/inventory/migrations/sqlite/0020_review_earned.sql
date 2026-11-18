-- +goose Up
-- A private-address device that was held out of To review (quiet) and then showed a reason to look (an open service, a stay past a
-- day, a finding, a honeypot hit) keeps that reason: review_earned_at is when it was set, in the write that announced it. Once set the
-- device stays in To review until a person approves or ignores it, and its new-device notice is sent only by the write that set it.
-- Devices that already have such a reason are marked at upgrade without a notice. Forward-only (DATA_MODEL 6, rule 1).
ALTER TABLE inv_asset ADD COLUMN review_earned_at TEXT;
UPDATE inv_asset SET review_earned_at = last_seen WHERE approved = 0
    AND (EXISTS (SELECT 1 FROM inv_service s WHERE s.asset_id = inv_asset.id) OR julianday(last_seen) - julianday(first_seen) > 1.0);
