-- +goose Up
-- Slice 3b (D-241): the buttons of a Slack approval message are removed (chat.update) once the request is finally decided or has
-- ended (docs/specs/approval-tokens.md 5). Each posted message keeps how far the removal got:
--   shown    the message with buttons is in the channel
--   remove   the request was finally decided or has ended: the deliver job rewrites the message without buttons
--   removed  done, or given up after 5 tries (tries)
-- outcome is how the request ended, one of a fixed set (the line written into the message; never text from the event).
ALTER TABLE notify_slack_button ADD COLUMN state TEXT NOT NULL DEFAULT 'shown' CHECK (state IN ('shown', 'remove', 'removed'));
ALTER TABLE notify_slack_button ADD COLUMN outcome TEXT CHECK (outcome IS NULL OR outcome IN ('approved', 'rejected', 'expired', 'cancelled', 'ended'));
ALTER TABLE notify_slack_button ADD COLUMN tries INTEGER NOT NULL DEFAULT 0 CHECK (tries BETWEEN 0 AND 5);
CREATE INDEX notify_slack_button_state_ix ON notify_slack_button (state, expires_at);
-- notify_slack_final: requests whose final decision arrived (response.decision.made, final=true). The Slack message of a request is
-- recorded after every message of the request went out, so the decision can arrive first (an approver on another channel pressed
-- while the rest were being sent); the message recorded then is marked for removal at once. Pruned a week after at.
CREATE TABLE notify_slack_final (
    request_id TEXT NOT NULL PRIMARY KEY CHECK (length(request_id) BETWEEN 1 AND 128),
    outcome    TEXT NOT NULL CHECK (outcome IN ('approved', 'rejected', 'expired', 'cancelled', 'ended')),
    at         TEXT NOT NULL CHECK (at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z')
);
CREATE INDEX notify_slack_final_at_ix ON notify_slack_final (at);
