-- +goose Up
-- Step-up codes (D-98) and sign-in codes keep separate hourly budgets: a stolen session that asks for step-up
-- codes must not use up the owner's five sign-in codes an hour. kind says which budget a send counts against.
-- Forward-only (DATA_MODEL 6, rule 1): there is deliberately no Down section.

ALTER TABLE core_email_code_send ADD COLUMN kind TEXT NOT NULL DEFAULT 'signin' CHECK (kind IN ('signin', 'stepup'));
