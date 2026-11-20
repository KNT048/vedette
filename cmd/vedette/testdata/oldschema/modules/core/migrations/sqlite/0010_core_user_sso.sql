-- +goose Up
-- D-195: an account made by an SSO sign-in (module auth-oidc) is keyed by the identity provider's (iss, sub), never by email.
-- Both columns are NULL for an account that signs in with a password; both are set for an SSO account, whose password_hash is
-- the hash of a random value nobody holds (no password sign-in). core owns the table; auth-oidc reaches it only through core/auth.
-- Forward-only (DATA_MODEL 6, rule 1): there is deliberately no Down section.

ALTER TABLE core_user ADD COLUMN sso_issuer TEXT CHECK (sso_issuer IS NULL OR (sso_issuer GLOB 'https://*' AND length(sso_issuer) <= 2048));
ALTER TABLE core_user ADD COLUMN sso_subject TEXT CHECK (sso_subject IS NULL OR length(sso_subject) BETWEEN 1 AND 255);

CREATE UNIQUE INDEX core_user_sso_idx ON core_user (sso_issuer, sso_subject) WHERE sso_issuer IS NOT NULL;
