-- +goose Up
-- WP-31 R3 (D-191, S-RESP-2): an approver proves the address or ID an administrator typed for them on a notify channel. A proof counts
-- only while the channel's list (and, for email, the sign-in email) still holds exactly this address. One proof per person and channel.
CREATE TABLE resp_identity (
    user_id   TEXT NOT NULL,
    channel   TEXT NOT NULL CHECK (channel IN ('email', 'slack', 'telegram', 'zalo', 'zalo-personal')),
    address   TEXT NOT NULL CHECK (length(address) BETWEEN 1 AND 320),
    linked_at TEXT NOT NULL,
    PRIMARY KEY (user_id, channel)
);
-- The link code waiting for a person and channel: only its hash (SHA-256 of a fixed label, the person, the channel, the address and the code).
-- A new code replaces the old one; 5 wrong tries delete it.
CREATE TABLE resp_link_codes (
    user_id    TEXT NOT NULL,
    channel    TEXT NOT NULL CHECK (channel IN ('email', 'slack', 'telegram', 'zalo', 'zalo-personal')),
    address    TEXT NOT NULL CHECK (length(address) BETWEEN 1 AND 320),
    code_hash  TEXT NOT NULL CHECK (length(code_hash) = 64),
    expires_at TEXT NOT NULL,
    sent_at    TEXT NOT NULL,
    tries      INTEGER NOT NULL DEFAULT 0 CHECK (tries BETWEEN 0 AND 5),
    PRIMARY KEY (user_id, channel)
);
