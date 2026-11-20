-- +goose Up
-- auth-oidc (S-CORE-3, D-194..D-196). Only package modules/auth-oidc writes these tables. Accounts and sessions stay in core
-- (core_user.sso_issuer/sso_subject, core_session), reached through core/auth. Forward-only (DATA_MODEL 6): no Down section.

-- The one SSO configuration (id = 1). The client secret is in core_secret (purpose oidc_config.client_secret); secret_last4 is copied
-- here for the API. redirect_uri is pinned from the origin of the administrator who saved (D-194 (5)). role_map is a JSON array of
-- {group, role}, at most 10 rows; default_role NULL = no access.
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
);

-- A sign-in that started and has not come back (D-194 (4)): only SHA-256 of state and binding; nonce and the PKCE verifier are
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
