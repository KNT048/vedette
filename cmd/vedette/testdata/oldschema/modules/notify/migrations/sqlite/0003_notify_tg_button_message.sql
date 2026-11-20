-- +goose Up
-- Slice 13b-8 (2): the buttons of a Telegram approval message are removed once the request is finally decided or has ended
-- (docs/specs/approval-tokens.md 6). The row of the request keeps where the message is and how far the removal got:
--   none    the message is not known yet (being sent, or the send failed)
--   shown   the message with buttons is in the chat (message_id, chat_id)
--   remove  the request was finally decided or has ended: the deliver job takes the buttons off
--   removed done, or given up after 5 tries (tries)
ALTER TABLE notify_tg_button ADD COLUMN message_id INTEGER CHECK (message_id IS NULL OR message_id BETWEEN 1 AND 9007199254740992);
-- chat_id is the chat Telegram names in its sendMessage answer (checked: a plain number, at most 21 characters with its sign), never
-- the configured chat_id text: the CHECK accepts exactly what the parser lets through, so a valid answer never rolls back the send record.
ALTER TABLE notify_tg_button ADD COLUMN chat_id TEXT CHECK (chat_id IS NULL OR length(chat_id) BETWEEN 1 AND 21);
ALTER TABLE notify_tg_button ADD COLUMN state TEXT NOT NULL DEFAULT 'none' CHECK (state IN ('none', 'shown', 'remove', 'removed'));
ALTER TABLE notify_tg_button ADD COLUMN tries INTEGER NOT NULL DEFAULT 0 CHECK (tries BETWEEN 0 AND 5);
CREATE INDEX notify_tg_button_state_ix ON notify_tg_button (state, expires_at);
