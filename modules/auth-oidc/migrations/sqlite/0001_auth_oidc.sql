-- +goose Up
-- The whole schema of the auth-oidc module. It is edited in place until the first public release; docs/SCHEMA.sql
-- shows the schema of every module together. Forward-only: there is no Down section.

CREATE TABLE oidc_config (
    id            INTEGER NOT NULL PRIMARY KEY CHECK (id = 1),
    issuer        TEXT    NOT NULL CHECK (issuer GLOB 'https://*' AND length(issuer) <= 2048),
    client_id     TEXT    NOT NULL CHECK (length(client_id) BETWEEN 1 AND 200),
    secret_id     TEXT    NOT NULL REFERENCES core_secret (id),
    secret_last4  TEXT    NOT NULL CHECK (length(secret_last4) = 4),
    scopes        TEXT    NOT NULL CHECK (length(scopes) BETWEEN 6 AND 700),
    groups_claim  TEXT    NOT NULL CHECK (length(groups_claim) BETWEEN 1 AND 64),
    default_role  TEXT    CHECK (default_role IS NULL OR default_role IN ('viewer', 'operator', 'admin')),
    role_map      TEXT    NOT NULL CHECK (json_valid(role_map) AND json_type(role_map) = 'array'),
    redirect_uri  TEXT    NOT NULL CHECK (length(redirect_uri) BETWEEN 1 AND 2048),
    updated_at    TEXT    NOT NULL
, ca_pem TEXT NOT NULL DEFAULT '' CHECK (length(ca_pem) <= 65536));

-- A sign-in that started and has not come back: only SHA-256 of state and binding; nonce and the PKCE verifier are
-- needed in the clear at the callback. Single use (deleted at the first callback), 10 minutes, at most 1000 rows (oldest dropped).
-- issuer, client_id and redirect_uri are the configuration at start: a change in between makes the callback sso_expired.
CREATE TABLE oidc_flow (
    state_hash    TEXT    NOT NULL PRIMARY KEY CHECK (length(state_hash) = 64),
    binding_hash  TEXT    NOT NULL CHECK (length(binding_hash) = 64),
    nonce         TEXT    NOT NULL CHECK (length(nonce) BETWEEN 32 AND 128),
    verifier      TEXT    NOT NULL CHECK (length(verifier) BETWEEN 43 AND 128),
    issuer        TEXT    NOT NULL,
    client_id     TEXT    NOT NULL,
    redirect_uri  TEXT    NOT NULL,
    created_at    TEXT    NOT NULL,
    expires_at    TEXT    NOT NULL
);

CREATE INDEX oidc_flow_created_idx ON oidc_flow (created_at);
