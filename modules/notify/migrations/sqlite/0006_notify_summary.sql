-- +goose Up
-- The daily summary (core/schedule owner notify.summary): one row each time its schedule came due. The schedule's transaction writes
-- the row as 'due'; the summary job takes it ('sending' before anything is sent, so a crash never sends it twice), then keeps what it
-- did: 'sent' (at least one channel was tried), 'empty' (nothing to tell), 'skipped' (found too late, or no channel on). A summary
-- covers what came in since the due time of the summary before it. Add-only and forward-only: there is no Down section.
CREATE TABLE notify_summary (
    id      TEXT NOT NULL PRIMARY KEY CHECK (length(id) BETWEEN 1 AND 64),
    due_at  TEXT NOT NULL CHECK (due_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    state   TEXT NOT NULL CHECK (state IN ('due', 'sending', 'sent', 'empty', 'skipped')),
    done_at TEXT CHECK (done_at IS NULL OR done_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z')
);
CREATE INDEX notify_summary_due_ix ON notify_summary (due_at);
