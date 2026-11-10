-- +goose Up
-- The nonce of the Approve/Reject buttons of a Telegram approval message (docs/specs/approval-tokens.md 6, slice 13b-8):
-- callback_data is "a:<request_id>:<nonce>" or "r:<request_id>:<nonce>", and the listener passes a press to the response
-- module only when the nonce matches the one sent for that request, so a press made up by a client is never a decision.
-- Only the SHA-256 (hex) of the nonce is kept. One row per request (one message per request on the Telegram channel);
-- rows are pruned a week after the request ends.
CREATE TABLE notify_tg_button (
    request_id TEXT NOT NULL PRIMARY KEY CHECK (length(request_id) BETWEEN 1 AND 50),
    nonce_hash TEXT NOT NULL CHECK (length(nonce_hash) = 64),
    expires_at TEXT NOT NULL CHECK (expires_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z')
);
CREATE INDEX notify_tg_button_expires_ix ON notify_tg_button (expires_at);
