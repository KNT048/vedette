-- +goose Up
-- first_enrolled_at is when a machine first enrolled with the token. A token with none expires a day after it was made (whatever its set
-- expiry); one that has enrolled a machine keeps its set expiry so more machines can join. Existing tokens: the oldest machine that
-- enrolled with it, else the time it last received data (a token whose machines are gone but that did report was used).
ALTER TABLE intake_agent_tokens ADD COLUMN first_enrolled_at TEXT;
UPDATE intake_agent_tokens SET first_enrolled_at = coalesce((SELECT min(enrolled_at) FROM intake_osquery_nodes n WHERE n.token_id = intake_agent_tokens.id), last_received);
