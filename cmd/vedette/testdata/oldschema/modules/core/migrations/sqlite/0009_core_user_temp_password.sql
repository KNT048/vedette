-- +goose Up
-- D-180: a password an administrator set (a new account, a reset) is temporary. temp_password_expires_at is NULL for an account whose
-- password the user chose (every account that existed before this column too: they are not flagged), and the time (72 hours after
-- the administrator set it) until which the temporary password may sign in. While it is set the session of that user may only read
-- /me, change the password and sign out; changing the password sets it back to NULL in the same transaction.
-- Forward-only (DATA_MODEL 6, rule 1): there is deliberately no Down section.

ALTER TABLE core_user ADD COLUMN temp_password_expires_at TEXT CHECK (temp_password_expires_at IS NULL OR temp_password_expires_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z');
