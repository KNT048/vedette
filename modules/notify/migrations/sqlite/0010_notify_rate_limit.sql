-- +goose Up
-- D-483: a message a provider refused with "too many requests" goes back to the queue (attempts counts the refusals, bounded in code),
-- and its one history row says "Delayed (rate limited)", which the GUI shows as delayed, not failed, without Resend.
ALTER TABLE notify_pending ADD COLUMN attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts BETWEEN 0 AND 100);
ALTER TABLE notify_send ADD COLUMN delayed INTEGER NOT NULL DEFAULT 0 CHECK (delayed IN (0, 1));
