-- +goose Up
-- Slice 3 (D-38, D-240): Slack approvals through Socket Mode.
-- notify_slack_button: the approval message the box posted with Approve/Reject buttons (chat.postMessage with the bot token). A press
-- is taken only when the message it came from (channel + ts) is one of these rows and the request has not ended: the Slack analogue of
-- the Telegram nonce check. No secret is kept: the button value is "a:<request_id>" or "r:<request_id>". One row per posted message
-- (a request sent again has two messages; both stay valid). Rows are pruned a week after their request ends.
CREATE TABLE notify_slack_button (
    request_id TEXT NOT NULL CHECK (length(request_id) BETWEEN 1 AND 128),
    channel_id TEXT NOT NULL CHECK (length(channel_id) BETWEEN 9 AND 13),
    ts         TEXT NOT NULL CHECK (ts GLOB '[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]'),
    expires_at TEXT NOT NULL CHECK (expires_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    PRIMARY KEY (request_id, channel_id, ts)
);
CREATE INDEX notify_slack_button_expires_ix ON notify_slack_button (expires_at);
-- notify_slack_team: the workspace id learned with auth.test for the bot token of the Slack channel at revision rev. A press from another
-- workspace is ignored. One row; learned again whenever the channel changes (rev).
CREATE TABLE notify_slack_team (
    id      INTEGER NOT NULL PRIMARY KEY CHECK (id = 1),
    rev     INTEGER NOT NULL,
    team_id TEXT    NOT NULL CHECK (length(team_id) BETWEEN 7 AND 21)
);
