-- +goose Up
-- WP-13b slice 13b-7 (D-96, spec approval-tokens.md 4.1 and 7.1): resp_tokens v2 holds the one-time approval links (kind 'link') and the Zalo
-- personal reply codes (kind 'code') of each approver. Only the hash is stored, never the token or the code. The table of part 1 was never written
-- (no row can exist), so it is dropped and made again. Forward-only (DATA_MODEL 6, rule 1).
DROP TABLE resp_tokens;
CREATE TABLE resp_tokens (
    -- link: SHA-256 (hex) of the 16 byte token id inside the token v1.<id>.<mac>; code: the code hash of spec 7.1
    token_hash TEXT NOT NULL PRIMARY KEY CHECK (length(token_hash) = 64),
    kind       TEXT NOT NULL CHECK (kind IN ('link', 'code')),
    -- code only: the decision the code stands for (an "A-" or an "R-" code); a link is decided on the page
    decision   TEXT CHECK (decision IN ('approve', 'reject')),
    action_id  TEXT NOT NULL,
    user_id    TEXT NOT NULL,
    address    TEXT NOT NULL,
    channel    TEXT NOT NULL CHECK (channel IN ('email', 'zalo', 'zalo-personal')),
    -- link only: the id of the key that signed it (notify names it)
    key_id     TEXT,
    expires_at TEXT NOT NULL,
    used_at    TEXT,
    CHECK ((kind = 'link' AND decision IS NULL AND key_id IS NOT NULL) OR (kind = 'code' AND decision IS NOT NULL AND key_id IS NULL))
);
CREATE INDEX resp_tokens_action ON resp_tokens (action_id);
-- the reply code of a sender is looked up by channel and address (13b-8)
CREATE INDEX resp_tokens_code ON resp_tokens (channel, address) WHERE kind = 'code' AND used_at IS NULL;
